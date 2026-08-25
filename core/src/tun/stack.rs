// asynchronous tun tcp packet engine with anti-dpi packet splitting

use super::checksum::Checksum;
use super::device::TunDevice;
use crate::engine::pipeline::EngineMetrics;
use crate::strategy::split::SniSplitter;
use crate::strategy::BypassMode;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::Mutex;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct FlowKey {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

pub struct TunStack;

impl TunStack {
    // starts the packet processing loop over the virtual tun interface
    pub async fn run(
        tun: Arc<TunDevice>,
        _mode: BypassMode,
        metrics: Arc<EngineMetrics>,
    ) -> std::io::Result<()> {
        let flows: Arc<Mutex<HashMap<FlowKey, Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let mut packet_buf = vec![0u8; 65535];

        loop {
            let n = tun.read_packet(&mut packet_buf).await?;
            if n < 40 {
                continue;
            }

            let packet = &packet_buf[..n];

            // 1. inspect ipv4 header
            let version = packet[0] >> 4;
            if version != 4 {
                continue;
            }

            let ihl = (packet[0] & 0x0f) as usize * 4;
            let protocol = packet[9];
            if protocol != 6 || n < ihl + 20 {
                continue; // only tcp
            }

            let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

            // 2. inspect tcp header
            let tcp = &packet[ihl..];
            let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
            let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
            let tcp_offset = (tcp[12] >> 4) as usize * 4;
            let flags = tcp[13];

            let syn = (flags & 0x02) != 0;
            let ack = (flags & 0x10) != 0;
            let fin = (flags & 0x01) != 0;
            let rst = (flags & 0x04) != 0;

            let payload = if tcp.len() > tcp_offset {
                &tcp[tcp_offset..]
            } else {
                &[]
            };

            let key = FlowKey {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            };

            // handle new tcp syn connection
            if syn && !ack {
                let (tx, mut rx) = channel::<Vec<u8>>(128);
                {
                    let mut lock = flows.lock().await;
                    lock.insert(key.clone(), tx);
                }

                let tun_clone = Arc::clone(&tun);
                let metrics_clone = Arc::clone(&metrics);
                let flows_clone = Arc::clone(&flows);
                let key_clone = key.clone();

                tokio::spawn(async move {
                    metrics_clone.total_connections.fetch_add(1, Ordering::Relaxed);

                    // 1. send syn-ack to client via tun
                    let client_seq = seq;
                    let our_seq: u32 = 0x1000;
                    Self::send_tcp_packet(
                        &tun_clone,
                        dst_ip,
                        src_ip,
                        dst_port,
                        src_port,
                        our_seq,
                        client_seq.wrapping_add(1),
                        0x12, // syn + ack
                        &[],
                    ).await;

                    // 2. establish outbound connection with socket mark to avoid routing loop
                    let target_addr = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));
                    let remote_stream = match TcpStream::connect(target_addr).await {
                        Ok(s) => {
                            let _ = s.set_nodelay(true);
                            unsafe {
                                let mark: u32 = 0x1337;
                                libc::setsockopt(
                                    s.as_raw_fd(),
                                    libc::SOL_SOCKET,
                                    libc::SO_MARK,
                                    &mark as *const _ as *const libc::c_void,
                                    std::mem::size_of::<u32>() as libc::socklen_t,
                                );
                            }
                            s
                        }
                        Err(_) => {
                            flows_clone.lock().await.remove(&key_clone);
                            return;
                        }
                    };

                    let (mut remote_read, mut remote_write) = remote_stream.into_split();

                    let current_our_seq = Arc::new(AtomicU32::new(our_seq.wrapping_add(1)));
                    let current_client_seq = Arc::new(AtomicU32::new(client_seq.wrapping_add(1)));

                    // 3. handle client data incoming from tun queue
                    let tun_writer = Arc::clone(&tun_clone);
                    let our_seq_ref = Arc::clone(&current_our_seq);
                    let client_seq_ref = Arc::clone(&current_client_seq);

                    let client_task = async {
                        while let Some(data) = rx.recv().await {
                            if !data.is_empty() {
                                // apply anti-dpi split on tls clienthello
                                if data.len() > 5 && data[0] == 0x16 {
                                    metrics_clone.bypassed_tls_sessions.fetch_add(1, Ordering::Relaxed);
                                    let _ = SniSplitter::send_split(&mut remote_write, &data, 1).await;
                                } else {
                                    let _ = remote_write.write_all(&data).await;
                                    let _ = remote_write.flush().await;
                                }
                                let new_c_seq = client_seq_ref.fetch_add(data.len() as u32, Ordering::Relaxed).wrapping_add(data.len() as u32);
                                let cur_o_seq = our_seq_ref.load(Ordering::Relaxed);

                                Self::send_tcp_packet(
                                    &tun_writer,
                                    dst_ip,
                                    src_ip,
                                    dst_port,
                                    src_port,
                                    cur_o_seq,
                                    new_c_seq,
                                    0x10, // ack
                                    &[],
                                ).await;
                            }
                        }
                    };

                    // 4. handle remote data returning from server to tun
                    let tun_remote_writer = Arc::clone(&tun_clone);
                    let our_seq_remote = Arc::clone(&current_our_seq);
                    let client_seq_remote = Arc::clone(&current_client_seq);

                    let remote_task = async {
                        let mut r_buf = vec![0u8; 4096];
                        while let Ok(n) = remote_read.read(&mut r_buf).await {
                            if n == 0 { break; }
                            let cur_o_seq = our_seq_remote.fetch_add(n as u32, Ordering::Relaxed);
                            let cur_c_seq = client_seq_remote.load(Ordering::Relaxed);

                            Self::send_tcp_packet(
                                &tun_remote_writer,
                                dst_ip,
                                src_ip,
                                dst_port,
                                src_port,
                                cur_o_seq,
                                cur_c_seq,
                                0x18, // psh + ack
                                &r_buf[..n],
                            ).await;
                        }
                    };

                    tokio::select! {
                        _ = client_task => {},
                        _ = remote_task => {},
                    }

                    flows_clone.lock().await.remove(&key_clone);
                });
            } else if let Some(tx) = flows.lock().await.get(&key) {
                if !payload.is_empty() {
                    let _ = tx.send(payload.to_vec()).await;
                }
                if fin || rst {
                    flows.lock().await.remove(&key);
                }
            }
        }
    }

    // constructs and sends a raw ipv4+tcp packet directly to tun
    async fn send_tcp_packet(
        tun: &TunDevice,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) {
        let ip_len = 20 + 20 + payload.len();
        let mut packet = vec![0u8; ip_len];

        // 1. ipv4 header
        packet[0] = 0x45; // version 4, ihl 5
        packet[1] = 0x00; // dscp/ecn
        packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x4242u16.to_be_bytes()); // id
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
        packet[8] = 64; // ttl
        packet[9] = 6; // protocol tcp
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        let ip_checksum = Checksum::compute(&packet[0..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        // 2. tcp header
        let tcp_start = 20;
        packet[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
        packet[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
        packet[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
        packet[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
        packet[tcp_start + 12] = 0x50; // data offset (5 * 4 = 20 bytes)
        packet[tcp_start + 13] = flags;
        packet[tcp_start + 14..tcp_start + 16].copy_from_slice(&65535u16.to_be_bytes()); // window size

        if !payload.is_empty() {
            packet[tcp_start + 20..].copy_from_slice(payload);
        }

        let tcp_checksum = Checksum::compute_tcp(src_ip, dst_ip, &packet[tcp_start..]);
        packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        let _ = tun.write_packet(&packet).await;
    }
}
