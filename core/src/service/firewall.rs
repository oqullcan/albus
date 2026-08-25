// native netfilter / iptables lifecycle manager with raii drop guard

use std::process::Command;

pub struct FirewallGuard {
    active: bool,
}

impl FirewallGuard {
    pub fn enable(http_port: u16, custom_bootstraps: &[String]) -> Self {
        firewall_enable(http_port, custom_bootstraps);
        Self { active: true }
    }

    pub fn disarm(&mut self) {
        if self.active {
            firewall_disable();
            self.active = false;
        }
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if self.active {
            firewall_disable();
        }
    }
}

fn run_cmd(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

fn run_cmd_success(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn firewall_disable() {
    // 1. Remove jumps from main tables in safe unrolled loops
    while run_cmd_success("iptables", &["-D", "OUTPUT", "-j", "ALBUS_OUT"]) {}
    while run_cmd_success("iptables", &["-D", "INPUT", "-j", "ALBUS_IN"]) {}
    while run_cmd_success("ip6tables", &["-D", "OUTPUT", "-j", "ALBUS_OUT6"]) {}
    while run_cmd_success("ip6tables", &["-D", "INPUT", "-j", "ALBUS_IN6"]) {}

    while run_cmd_success("iptables", &["-D", "OUTPUT", "-j", "ALBUS_QUIC"]) {}
    while run_cmd_success("ip6tables", &["-D", "OUTPUT", "-j", "ALBUS_V6"]) {}
    while run_cmd_success("ip6tables", &["-D", "INPUT", "-j", "ALBUS_V6_IN"]) {}

    while run_cmd_success("iptables", &["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "ALBUS"]) {}
    while run_cmd_success("iptables", &["-t", "nat", "-D", "OUTPUT", "-j", "ALBUS"]) {}
    while run_cmd_success("iptables", &["-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ALBUS_DNS"]) {}
    while run_cmd_success("iptables", &["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ALBUS_DNS"]) {}
    while run_cmd_success("iptables", &["-t", "nat", "-D", "OUTPUT", "-j", "ALBUS_DNS"]) {}

    while run_cmd_success("iptables", &["-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", "ALBUS"]) {}
    while run_cmd_success("iptables", &["-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "ALBUS_DNS"]) {}
    while run_cmd_success("iptables", &["-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "53", "-j", "ALBUS_DNS"]) {}
    while run_cmd_success("iptables", &["-t", "nat", "-D", "PREROUTING", "-j", "ALBUS"]) {}
    while run_cmd_success("iptables", &["-t", "nat", "-D", "PREROUTING", "-j", "ALBUS_DNS"]) {}

    while run_cmd_success("iptables", &["-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1360"]) {}

    // 2. Flush and delete custom chains
    run_cmd("iptables", &["-F", "ALBUS_OUT"]);
    run_cmd("iptables", &["-X", "ALBUS_OUT"]);
    run_cmd("iptables", &["-F", "ALBUS_IN"]);
    run_cmd("iptables", &["-X", "ALBUS_IN"]);
    run_cmd("ip6tables", &["-F", "ALBUS_OUT6"]);
    run_cmd("ip6tables", &["-X", "ALBUS_OUT6"]);
    run_cmd("ip6tables", &["-F", "ALBUS_IN6"]);
    run_cmd("ip6tables", &["-X", "ALBUS_IN6"]);

    run_cmd("iptables", &["-F", "ALBUS_QUIC"]);
    run_cmd("iptables", &["-X", "ALBUS_QUIC"]);
    run_cmd("ip6tables", &["-F", "ALBUS_V6"]);
    run_cmd("ip6tables", &["-X", "ALBUS_V6"]);
    run_cmd("ip6tables", &["-F", "ALBUS_V6_IN"]);
    run_cmd("ip6tables", &["-X", "ALBUS_V6_IN"]);

    run_cmd("iptables", &["-t", "nat", "-F", "ALBUS"]);
    run_cmd("iptables", &["-t", "nat", "-X", "ALBUS"]);
    run_cmd("iptables", &["-t", "nat", "-F", "ALBUS_DNS"]);
    run_cmd("iptables", &["-t", "nat", "-X", "ALBUS_DNS"]);

    // 3. Clean legacy standalone drop rules
    while run_cmd_success("iptables", &["-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP"]) {}
    while run_cmd_success("iptables", &["-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]) {}
    while run_cmd_success("ip6tables", &["-D", "OUTPUT", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "REJECT", "--reject-with", "tcp-reset"]) {}
    while run_cmd_success("ip6tables", &["-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "REJECT"]) {}
    while run_cmd_success("ip6tables", &["-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REJECT"]) {}

    // 4. Flush conntrack if available
    run_cmd("conntrack", &["-F"]);
}

pub fn firewall_enable(http_port: u16, custom_bootstraps: &[String]) {
    firewall_disable();

    let port_str = http_port.to_string();

    // 1. Filter chains
    run_cmd("iptables", &["-N", "ALBUS_OUT"]);
    run_cmd("iptables", &["-A", "ALBUS_OUT", "-m", "mark", "--mark", "0x1337", "-j", "RETURN"]);
    run_cmd("iptables", &["-A", "ALBUS_OUT", "-p", "udp", "--dport", "443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]);

    run_cmd("iptables", &["-N", "ALBUS_IN"]);
    run_cmd("iptables", &["-A", "ALBUS_IN", "!", "-i", "lo", "-p", "tcp", "--dport", &port_str, "-j", "DROP"]);
    run_cmd("iptables", &["-A", "ALBUS_IN", "!", "-i", "lo", "-p", "udp", "--dport", "5300", "-j", "DROP"]);
    run_cmd("iptables", &["-A", "ALBUS_IN", "!", "-i", "lo", "-p", "tcp", "--dport", "5300", "-j", "DROP"]);

    run_cmd("ip6tables", &["-N", "ALBUS_OUT6"]);
    run_cmd("ip6tables", &["-A", "ALBUS_OUT6", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "REJECT", "--reject-with", "tcp-reset"]);
    run_cmd("ip6tables", &["-A", "ALBUS_OUT6", "-p", "udp", "--dport", "443", "-j", "REJECT"]);
    run_cmd("ip6tables", &["-A", "ALBUS_OUT6", "-p", "udp", "--dport", "53", "-j", "REJECT"]);

    run_cmd("ip6tables", &["-N", "ALBUS_IN6"]);
    run_cmd("ip6tables", &["-A", "ALBUS_IN6", "!", "-i", "lo", "-p", "tcp", "--dport", &port_str, "-j", "DROP"]);
    run_cmd("ip6tables", &["-A", "ALBUS_IN6", "!", "-i", "lo", "-p", "udp", "--dport", "5300", "-j", "DROP"]);
    run_cmd("ip6tables", &["-A", "ALBUS_IN6", "!", "-i", "lo", "-p", "tcp", "--dport", "5300", "-j", "DROP"]);

    // 2. NAT TCP Chain
    run_cmd("iptables", &["-t", "nat", "-N", "ALBUS"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-m", "mark", "--mark", "0x1337", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-d", "0.0.0.0/8", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-d", "10.0.0.0/8", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-d", "127.0.0.0/8", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-d", "169.254.0.0/16", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-d", "172.16.0.0/12", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-d", "192.168.0.0/16", "-j", "RETURN"]);

    // Direct bypass for known upstream DoH resolvers
    let doh_ips = [
        "9.9.9.9",
        "149.112.112.112",
        "1.1.1.1",
        "1.0.0.1",
        "94.140.14.14",
        "94.140.15.15",
        "45.90.28.0/24",
        "45.90.30.0/24",
    ];
    for ip in &doh_ips {
        run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-d", ip, "-j", "RETURN"]);
    }

    // Custom bootstrap bypass
    for cb in custom_bootstraps {
        for part in cb.split([',', ' ', ';']) {
            let trimmed = part.trim();
            if trimmed.parse::<std::net::Ipv4Addr>().is_ok() {
                run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-d", trimmed, "-j", "RETURN"]);
            }
        }
    }

    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", &port_str]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", &port_str]);

    // 3. NAT DNS Chain
    run_cmd("iptables", &["-t", "nat", "-N", "ALBUS_DNS"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS_DNS", "-m", "mark", "--mark", "0x1337", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS_DNS", "-d", "127.0.0.0/8", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS_DNS", "-d", "10.0.0.0/8", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS_DNS", "-d", "172.16.0.0/12", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS_DNS", "-d", "192.168.0.0/16", "-j", "RETURN"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS_DNS", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5300"]);
    run_cmd("iptables", &["-t", "nat", "-A", "ALBUS_DNS", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5300"]);

    // 4. Link into system packet flow
    run_cmd("iptables", &["-I", "OUTPUT", "1", "-j", "ALBUS_OUT"]);
    run_cmd("iptables", &["-I", "INPUT", "1", "-j", "ALBUS_IN"]);
    run_cmd("ip6tables", &["-I", "OUTPUT", "1", "-j", "ALBUS_OUT6"]);
    run_cmd("ip6tables", &["-I", "INPUT", "1", "-j", "ALBUS_IN6"]);

    run_cmd("iptables", &["-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "-j", "ALBUS"]);
    run_cmd("iptables", &["-t", "nat", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "53", "-j", "ALBUS_DNS"]);
    run_cmd("iptables", &["-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "--dport", "53", "-j", "ALBUS_DNS"]);
    run_cmd("iptables", &["-t", "mangle", "-I", "OUTPUT", "1", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", "1360"]);
}
