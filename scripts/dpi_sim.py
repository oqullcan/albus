#!/usr/bin/env python3
"""Minimal L3 DPI simulator + harness for albus bypass validation (stdlib only).

Model: a passive observer on an interface reassembles TCP streams. When it
extracts a complete SNI from the FIRST segment of a ClientHello it injects a
spoofed TCP RST (fail-closed DPI). It stays silent when:
  - the ClientHello is fragmented across segments (MSS-clamp evasion), or
  - overlapping/duplicate sequence ranges appear (fake-injection desync).

Subcommands:
  stub    TLS stub server (self-signed cert via openssl CLI) on 127.0.0.1:9443
  sim     sniffer/RST injector on an interface (default: lo), needs root
  client  one TLS handshake with explicit SNI against 127.0.0.1:9443
  run     orchestrated lab: stub + sim + per-target clients, verdict table

Add future targets to TARGETS (or pass --targets host1,host2).
"""

from __future__ import annotations

import argparse
import json
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

# Extend freely: plain hostnames, SNI is set explicitly by the client.
TARGETS = ["roblox.com", "discord.com"]
# Port 443 (not a high port): the eBPF sock_ops hook only tracks target
# ports (default [443]). A 9443 stub would bypass shaping entirely and
# every run would RST even with albus on — a false negative.
STUB_PORT = 443
FLOW_TIMEOUT = 4.0

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def log(event: str, **fields: object) -> None:
    rec = {"ts": round(time.time(), 3), "event": event}
    rec.update(fields)
    print(json.dumps(rec), flush=True)


def tcp_checksum(src: bytes, dst: bytes, segment: bytes) -> int:
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(segment))
    data = pseudo + segment
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip_checksum(header: bytes) -> int:
    """Ones-complement checksum over a header with a zeroed checksum field."""
    s = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def parse_sni(stream: bytes) -> str | None:
    """Extract SNI from reassembled bytes starting at a TLS record."""
    try:
        if len(stream) < 5 or stream[0] != 0x16:
            return None
        rec_len = struct.unpack("!H", stream[3:5])[0]
        if len(stream) < 5 + rec_len:
            return None
        hs = stream[5 : 5 + rec_len]
        if len(hs) < 4 or hs[0] != 0x01:
            return None
        hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
        body = hs[4 : 4 + hs_len]
        if len(body) < 34:
            return None
        pos = 34
        # session id (variable; TLS 1.3 clients send 32 random bytes here)
        if pos >= len(body):
            return None
        sid_len = body[pos]
        pos += 1 + sid_len
        if pos + 2 > len(body):
            return None
        cs_len = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2 + cs_len
        if pos >= len(body):  # compression methods
            return None
        pos += 1 + body[pos]
        if pos + 2 > len(body):
            return None
        ext_len = struct.unpack("!H", body[pos : pos + 2])[0]
        pos += 2
        end = pos + ext_len
        while pos + 4 <= min(end, len(body)):
            etype = struct.unpack("!H", body[pos : pos + 2])[0]
            elen = struct.unpack("!H", body[pos + 2 : pos + 4])[0]
            if etype == 0x0000:
                ed = body[pos + 4 : pos + 4 + elen]
                if len(ed) < 2:
                    return None
                ln = struct.unpack("!H", ed[:2])[0]
                p = 2
                while p + 3 <= len(ed):
                    if ed[p] != 0:
                        return None
                    nl = struct.unpack("!H", ed[p + 1 : p + 3])[0]
                    name = ed[p + 3 : p + 3 + nl]
                    return name.decode("ascii", errors="replace")
                return None
            pos += 4 + elen
    except (IndexError, struct.error):
        return None
    return None


def parse_frame(frame: bytes):
    """Return (src_ip, dst_ip, src_port, dst_port, seq, payload, tcp_csum_ok,
    csum_field_zero).
    Handles raw IP (loopback AF_PACKET) and Ethernet-prefixed frames."""
    if len(frame) < 1:
        return None
    ver = frame[0] >> 4
    off = 0
    if ver != 4:
        if len(frame) > 14 and (frame[14] >> 4) == 4:
            off = 14  # ethernet header present
        else:
            return None
    if len(frame) < off + 20:
        return None
    ihl = (frame[off] & 0x0F) * 4
    if ihl < 20 or len(frame) < off + ihl + 20:
        return None
    if frame[off + 9] != 6:
        return None
    src = frame[off + 12 : off + 16]
    dst = frame[off + 16 : off + 20]
    t = off + ihl
    src_port, dst_port = struct.unpack("!HH", frame[t : t + 4])
    seq = struct.unpack("!I", frame[t + 4 : t + 8])[0]
    doff = (frame[t + 12] >> 4) * 4
    if doff < 20 or len(frame) < t + doff:
        return None
    payload = frame[t + doff :]
    seg = frame[t : t + doff] + payload
    recv_sum = struct.unpack("!H", frame[t + 16 : t + 18])[0]
    zeroed = seg[:16] + b"\x00\x00" + seg[18:]
    ok = tcp_checksum(src, dst, zeroed) == recv_sum
    return (src, dst, src_port, dst_port, seq, payload, ok, recv_sum == 0)


def send_rst(src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int, seq: int) -> None:
    """Spoofed TCP RST from server side (needs root + raw socket)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 40, 0x1234, 0x4000, 64, 6, 0, src_ip, dst_ip
        )
        tcp = struct.pack("!HHIIHHHH", src_port, dst_port, seq, 0, 0x50, 0x04, 0, 0)
        seg_sum = tcp_checksum(src_ip, dst_ip, tcp)
        tcp = tcp[:16] + struct.pack("!H", seg_sum) + tcp[18:]
        pkt = ip + tcp
        pkt = pkt[:10] + struct.pack("!H", ip_checksum(pkt[:20])) + pkt[12:]
        s.sendto(pkt, (socket.inet_ntoa(dst_ip), 0))
    finally:
        s.close()


# --------------------------------------------------------------------------
# stub TLS server (self-signed cert generated via openssl CLI)
# --------------------------------------------------------------------------

def ensure_cert(tmpdir: str) -> tuple[str, str]:
    cert, key = f"{tmpdir}/stub.crt", f"{tmpdir}/stub.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "2",
            "-subj", "/CN=localhost",
        ],
        check=True, capture_output=True,
    )
    return cert, key


def run_stub(port: int, stop: threading.Event) -> None:
    import ssl

    with tempfile.TemporaryDirectory(prefix="albus-dpi-stub-") as tmpdir:
        try:
            cert, key = ensure_cert(tmpdir)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            log("stub_cert_failed", error=str(e))
            return
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(16)
        srv.settimeout(0.5)
        log("stub_listening", port=port)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                tls.settimeout(3.0)
                try:
                    tls.recv(1024)
                except OSError:
                    pass
                try:
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                except OSError:
                    pass
                try:
                    tls.close()
                except OSError:
                    pass
            except (ssl.SSLError, OSError):
                try:
                    conn.close()
                except OSError:
                    pass
        srv.close()


# --------------------------------------------------------------------------
# sim: passive observer + RST injector
# --------------------------------------------------------------------------

class Sim:
    def __init__(self, iface: str, blocklist: list[str]) -> None:
        self.iface = iface
        self.block = {b.lower() for b in blocklist}
        # Loopback captures carry partial (offloaded) checksums, so a
        # "wrong" checksum there proves nothing; only real interfaces get
        # the bad-checksum confusion signal. Overlap detection works
        # everywhere.
        self.check_csum = iface != "lo"
        self.flows: dict[tuple, dict] = {}
        self.decisions: dict[str, str] = {}
        # monotonic timestamps of desync evidence (overlap / bad checksum);
        # plus last-seen data segment time toward the stub (any SNI).
        self.confused: list[float] = []
        self.last_data_at: float = 0.0

    def run(self, stop: threading.Event) -> None:
        try:
            sniffer = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)
            )
        except PermissionError:
            log("sim_need_root")
            return
        sniffer.bind((self.iface, 0))
        sniffer.setblocking(False)
        log("sim_listening", iface=self.iface, block=sorted(self.block))
        while not stop.is_set():
            ready, _, _ = select.select([sniffer], [], [], 0.5)
            if not ready:
                self._expire()
                continue
            try:
                frame, _ = sniffer.recvfrom(65535)
            except OSError:
                continue
            self._packet(frame)
        sniffer.close()

    def _expire(self) -> None:
        now = time.monotonic()
        for k in [k for k, f in self.flows.items() if now - f["seen"] > FLOW_TIMEOUT]:
            del self.flows[k]

    def _packet(self, frame: bytes) -> None:
        parsed = parse_frame(frame)
        if not parsed:
            return
        src, dst, sport, dport, seq, payload, csum_ok, csum_zero = parsed
        if dport != STUB_PORT or not payload:
            return
        self.last_data_at = time.monotonic()
        key = (src, sport, dst, dport)
        if key not in self.flows:
            # forensic: first-segment length determines everything downstream
            # (whole hello => instant RST race; fragments => reassembly path)
            log("sim_first_seg", len=len(payload), sport=sport)
        flow = self.flows.setdefault(
            key, {"segs": [], "seen": time.monotonic(), "done": False}
        )
        flow["seen"] = time.monotonic()
        if flow["done"]:
            return
        # overlapping seq already seen => injected decoy confusion
        for (oseq, opay) in flow["segs"]:
            if oseq == seq and opay != payload and payload:
                flow["done"] = True
                self.confused.append(time.monotonic())
                log("sim_confused_overlap", sni="unknown")
                return
        # bad checksum => likely injected fake. Zero checksum fields are
        # checksum-offload artifacts (loopback), not confusion signals.
        if not csum_ok and not csum_zero and self.check_csum and payload:
            flow["done"] = True
            self.confused.append(time.monotonic())
            log("sim_confused_badsum", sni="unknown")
            return
        flow["segs"].append((seq, payload))
        flow["segs"].sort()
        stream = b"".join(p for _, p in flow["segs"])
        if len(stream) < 6:
            return
        # fragmented ClientHello (SNI not yet parseable across segments)?
        sni = parse_sni(stream)
        if sni is None:
            # need more segments unless stream already exceeds sane hello size
            if len(stream) > 4096:
                flow["done"] = True
            return
        flow["done"] = True
        first_len = len(flow["segs"][0][1])
        if sni.lower() in self.block:
            if first_len >= len(stream):
                # complete SNI in first segment: DPI wins, RST
                try:
                    send_rst(dst, src, dport, sport, seq + len(payload))
                    log("sim_rst", sni=sni, reason="clean-sni-first-segment")
                    self.decisions[sni] = "rst"
                except PermissionError:
                    log("sim_rst_failed_root", sni=sni)
                    self.decisions[sni] = "error"
            else:
                log("sim_pass_fragmented", sni=sni)
                self.decisions[sni] = "pass-fragmented"
        else:
            log("sim_pass_allowlist", sni=sni)
            self.decisions[sni] = "pass-allowlist"


# --------------------------------------------------------------------------
# client + orchestration
# --------------------------------------------------------------------------

def run_client(sni: str, port: int = STUB_PORT, timeout: float = 8.0) -> dict:
    import ssl

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    start = time.monotonic()
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        tls.settimeout(timeout)
        tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        data = tls.recv(4096)
        dt = round(time.monotonic() - start, 3)
        tls.close()
        return {"sni": sni, "handshake_ok": True, "seconds": dt, "bytes": len(data)}
    except Exception as e:  # noqa: BLE001 - test harness reports, never raises
        return {
            "sni": sni,
            "handshake_ok": False,
            "seconds": round(time.monotonic() - start, 3),
            "error": f"{type(e).__name__}: {e}",
        }


def cmd_run(args: argparse.Namespace) -> int:
    targets = args.targets.split(",") if args.targets else TARGETS
    stop = threading.Event()
    stub_thread = threading.Thread(target=run_stub, args=(args.port, stop), daemon=True)
    stub_thread.start()
    time.sleep(0.5)
    sim = Sim(args.iface, targets)
    sim_thread = threading.Thread(target=sim.run, args=(stop,), daemon=True)
    sim_thread.start()
    time.sleep(0.5)
    results = []
    for target in targets:
        # one handshake per target: the sim observes passively and decides.
        # Verdict follows SIM observations, not the handshake: on loopback
        # our own decoys poison the stub, so handshake_ok is meaningless.
        # rst => DPI won. Otherwise bypassed IFF the sim actually observed
        # data in this target's window (else inconclusive, not a pass).
        sim.last_data_at = 0.0
        window_start = time.monotonic()
        r = run_client(target, port=args.port)
        time.sleep(0.5)  # let the observer finish classifying
        decision = sim.decisions.get(target, "no-observation")
        observed = sim.last_data_at >= window_start
        if decision == "rst":
            bypassed: bool = False
        elif decision in ("pass-fragmented", "pass-allowlist") or (
            observed and len(sim.confused) > 0
        ):
            bypassed = True
        elif observed and decision == "no-observation":
            # traffic seen but never classifiable and never RST'd:
            # DPI observed yet could not act => defeated
            bypassed = True
        else:
            bypassed = False
        results.append(
            {
                "target": target,
                "handshake_ok": r["handshake_ok"],
                "sim_decision": decision,
                "bypassed": bypassed,
                "detail": r,
            }
        )
        log(
            "target_result",
            target=target,
            bypassed=bypassed,
            sim_decision=decision,
        )
    stop.set()
    print(json.dumps({"results": results}, indent=2))
    return 0 if all(r["bypassed"] for r in results) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="albus DPI simulator lab (stdlib only)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_stub = sub.add_parser("stub", help="run TLS stub server")
    p_stub.add_argument("--port", type=int, default=STUB_PORT)
    p_sim = sub.add_parser("sim", help="run sniffer/RST injector (needs root)")
    p_sim.add_argument("--iface", default="lo")
    p_sim.add_argument("--block", default=",".join(TARGETS))
    p_run = sub.add_parser("run", help="orchestrated lab run (needs root)")
    p_run.add_argument("--iface", default="lo")
    p_run.add_argument("--port", type=int, default=STUB_PORT)
    p_run.add_argument("--targets", default=",".join(TARGETS))
    p_client = sub.add_parser("client", help="single TLS handshake with SNI")
    p_client.add_argument("sni")
    p_client.add_argument("--port", type=int, default=STUB_PORT)
    args = ap.parse_args(argv)
    if args.cmd == "stub":
        stop = threading.Event()
        try:
            run_stub(args.port, stop)
        except KeyboardInterrupt:
            pass
        return 0
    if args.cmd == "sim":
        stop = threading.Event()
        try:
            Sim(args.iface, args.block.split(",")).run(stop)
        except KeyboardInterrupt:
            pass
        return 0
    if args.cmd == "client":
        print(json.dumps(run_client(args.sni, port=args.port), indent=2))
        return 0
    return cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
