//! terminal telemetry monitor for real-time packet flow inspection.

use std::io::{BufRead, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Strips terminal control sequences before a journal line reaches the TTY.
///
/// CLI-02: this was documented as the log-injection control but was wired only
/// to a static string, while the journal-follow child inherited the parent's
/// stdout and wrote journald MESSAGE bytes verbatim into the operator's
/// terminal. It is now on the path that actually carries log content, and it is
/// strengthened to match the claim:
///
///   * ESC-introduced sequences are bounded to a plausible escape length. The
///     old "skip until the first ASCII letter" loop was unbounded, so a bare
///     ESC mid-line would silently swallow every following character until it
///     happened to hit a letter — turning a one-line injection into silent
///     truncation of the rest of the line.
///   * all C0 and C1 control bytes are dropped except `\n` and `\t`. The old
///     version dropped only BEL and BS and let CR, VT, FF, NUL, 0x0E-0x1F and
///     the 0x80-0x9F C1 range through, all of which move the cursor, clear the
///     screen, or switch character sets.
///
/// Reachability today is blocked upstream by `label_is_safe` in the DNS parser,
/// so this is defence in depth: the invariant should not depend on a filter
/// that lives in an unrelated file staying strict.
fn strip_ansi(s: &str) -> String {
    /// Longest run of ESC-sequence body bytes we will skip before deciding the
    /// input is not a sequence we understand. Without a bound, a bare ESC
    /// mid-line would swallow the entire remainder of the line.
    const MAX_ESC_SEQ: usize = 64;

    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            if c == '\n' || c == '\t' {
                out.push(c);
            } else if (c as u32) < 0x20 || (0x7F..=0x9F).contains(&(c as u32)) {
                continue;
            } else {
                out.push(c);
            }
            continue;
        }

        // ESC introduces a sequence. Which byte terminates it depends on the
        // introducer, and getting this wrong is how a sanitizer leaks the rest
        // of the sequence into the terminal:
        //   ESC [  -> CSI, final byte is 0x40..=0x7E
        //   ESC ]  -> OSC, final byte is BEL or ST (ESC backslash)
        //   ESC other -> consumes exactly the one introducer byte
        let consumed = match chars.peek().copied() {
            Some('[') => {
                chars.next();
                take_until_final_byte(&mut chars, MAX_ESC_SEQ)
            }
            Some(']') => {
                chars.next();
                take_until_string_terminator(&mut chars, MAX_ESC_SEQ)
            }
            Some(intro) if ('\x20'..='\x2F').contains(&intro) => {
                // Charset designation such as ESC ( B: the introducer is
                // followed by one more final byte naming the set.
                chars.next();
                chars.next();
                2
            }
            Some(_) => {
                chars.next();
                1
            }
            None => 0,
        };
        let _ = consumed;
    }
    out
}

/// Consumes a CSI body up to its final byte (0x40..=0x7E), bounded.
fn take_until_final_byte<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
    max: usize,
) -> usize {
    let mut n = 0usize;
    for c in chars.by_ref() {
        n += 1;
        let v = c as u32;
        if (0x40..=0x7E).contains(&v) {
            break;
        }
        if n >= max {
            break;
        }
    }
    n
}

/// Consumes an OSC body up to BEL or ST (ESC \), bounded. OSC is explicitly
/// *not* terminated by an ASCII letter: `\x1b]0;title\x07` contains one, and
/// stopping there would leave "itle" to be printed as text.
fn take_until_string_terminator<I: Iterator<Item = char>>(
    chars: &mut std::iter::Peekable<I>,
    max: usize,
) -> usize {
    let mut n = 0usize;
    while let Some(c) = chars.next() {
        n += 1;
        if c == '\x07' {
            break;
        }
        if c == '\x1b' {
            // ST is ESC \ — consume the backslash too, then stop.
            if chars.peek() == Some(&'\\') {
                chars.next();
                n += 1;
            }
            break;
        }
        if n >= max {
            break;
        }
    }
    n
}

// renders clean terminal header and streams kernel flow events
pub fn run_monitor() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // clear screen and position cursor at origin
    print!("\x1b[2J\x1b[1;1H");

    // check systemd daemon execution state (absolute path, no shell)
    let is_active = crate::app::service::systemctl()
        .args(["is-active", "--quiet", "albus.service"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let dns_active = resolv.contains("127.0.0.1");

    let mut sink = std::io::stdout();

    println!("\x1b[1malbus monitor\x1b[0m \x1b[2m— realtime transport desynchronization & doh telemetry\x1b[0m\n");

    if is_active || dns_active {
        println!("  \x1b[1mstatus\x1b[0m    \x1b[32m● active\x1b[0m \x1b[2m(ebpf sock_ops attached)\x1b[0m");
    } else {
        println!("  \x1b[1mstatus\x1b[0m    \x1b[33m○ standby\x1b[0m \x1b[2m(run 'sudo albus run' or 'sudo albus service start')\x1b[0m");
    }

    println!("  \x1b[1mresolver\x1b[0m  127.0.0.1:53 \x1b[2m(quad9 doh • pqc ml-kem-768 • dnssec)\x1b[0m");
    println!("  \x1b[1mevasion\x1b[0m   mss 88b \x1b[2m(restore 600b) • auto-ttl • fake sni • quic drop\x1b[0m");
    println!("  \x1b[1mstorage\x1b[0m   volatile tmpfs \x1b[2m(/run — zero-disk footprint)\x1b[0m");
    println!("\n\x1b[2m──────────────────────────────────────────────────────────────────────────\x1b[0m\n");
    sink.flush()?;

    // Stream journal entries. The child's stdout is PIPED and filtered through
    // strip_ansi on a dedicated thread: the journal carries attacker-influenceable
    // content (DNS names, destinations), and inheriting this TTY would hand a
    // local UDP sender control sequences aimed at the operator's terminal.
    if is_active {
        let mut child = crate::app::service::journalctl()
            .args([
                "-u",
                "albus.service",
                "-f",
                "-n",
                "30",
                "--no-pager",
                "-o",
                "cat",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;

        if let Some(pipe) = child.stdout.take() {
            let reader = std::io::BufReader::new(pipe);
            let mut out = std::io::stdout();
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        // A malformed UTF-8 line must not abort the stream.
                        let _ = writeln!(out, "{}", strip_ansi(&l));
                        let _ = out.flush();
                    }
                    Err(_) => break,
                }
            }
        }

        let _ = child.wait();
    } else {
        println!(
            "{}",
            strip_ansi("waiting for engine events... (ctrl+c to exit)")
        );
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi() {
        assert_eq!(strip_ansi("\x1b[31mhello\x1b[0m"), "hello");
        assert_eq!(strip_ansi("clean"), "clean");
    }
}

#[cfg(test)]
mod log_injection_tests {
    use super::*;

    /// The fixture from the finding: an OSC 52 clipboard write, a CR that would
    /// overwrite the line, and a title-setting sequence.
    const HOSTILE: &str = "\x1b]52;c;cHduCg==\x07 dst=evil.example:443\r more";

    #[test]
    fn test_strip_ansi_removes_every_control_byte() {
        let out = strip_ansi(HOSTILE);
        assert!(!out.contains('\x1b'), "ESC must not survive: {:?}", out);
        assert!(
            !out.contains('\r'),
            "CR must not survive (it overwrites the line): {:?}",
            out
        );
        for c in out.chars() {
            let v = c as u32;
            assert!(
                v >= 0x20 && !(0x7F..=0x9F).contains(&v),
                "control byte U+{:04X} leaked through: {:?}",
                v,
                out
            );
        }
    }

    /// Every C0 and C1 byte, individually, must be dropped except \n and \t.
    #[test]
    fn test_all_c0_and_c1_bytes_are_dropped_except_newline_tab() {
        for v in (0x00u32..0x20).chain(0x7F..0xA0) {
            // ESC is excluded: it legitimately *starts* a sequence, so the
            // byte after it is consumed as part of the sequence, not as text.
            if v == 0x0A || v == 0x09 || v == 0x1B {
                continue;
            }
            let ch = char::from_u32(v).expect("valid scalar");
            let input = format!("a{}b", ch);
            let out = strip_ansi(&input);
            assert_eq!(out, "ab", "U+{:04X} must be stripped, got {:?}", v, out);
        }
        // SPACE is 0x20 -- printable, and must survive.
        assert_eq!(strip_ansi("a b"), "a b");
        // \n and \t are structural and must survive.
        assert_eq!(strip_ansi("a\nb\tc"), "a\nb\tc");
    }

    /// The old unbounded "skip to the first ASCII letter" loop swallowed every
    /// following character after a bare ESC. Bounding the skip means a bare ESC
    /// costs at most MAX_ESC_SEQ bytes and the rest of the line still renders.
    #[test]
    fn test_bare_esc_does_not_swallow_the_rest_of_the_line() {
        let out = strip_ansi("before\x1bafter-tail-text");
        assert!(
            out.contains("after") || out.contains("tail"),
            "a bare ESC must not silently eat the remainder of the line: {:?}",
            out
        );
        assert!(out.starts_with("before"));
    }

    /// A recognised sequence is consumed whole, including its final byte.
    #[test]
    fn test_recognised_sequences_are_consumed_whole() {
        assert_eq!(strip_ansi("\x1b[2J\x1b[1;1Hclean"), "clean");
        assert_eq!(strip_ansi("\x1b]0;title\x07text"), "text");
        assert_eq!(strip_ansi("\x1b(Bplain"), "plain");
    }

    /// CLI-02's regression guard: the journalctl child must keep a piped
    /// stdout, because that pipe is the only thing standing between a
    /// local UDP sender and the operator's terminal. This fails if anyone
    /// reverts to inheriting the TTY.
    #[test]
    fn test_journal_child_stdout_is_piped_not_inherited() {
        let src = include_str!("monitor.rs");
        // production prefix only: split on the FIRST cfg(test) so this
        // assertion cannot be satisfied by text inside the test module itself.
        let prod = src
            .split_once("#[cfg(test)]")
            .expect("test module marker")
            .0;
        let spawn_at = prod
            .find("journalctl()")
            .expect("journalctl spawn site (via the service::journalctl chokepoint)");
        let window = &prod[spawn_at..(spawn_at + 1200).min(prod.len())];
        assert!(
            window.contains("Stdio::piped()"),
            "journalctl stdout must be piped so strip_ansi can filter it: {}",
            window
        );
        // The filter must appear AFTER the spawn, on the lines that consume the
        // pipe -- a strip_ansi call earlier in the file proves nothing.
        let pipe_at = window
            .find("child.stdout.take()")
            .expect("the piped stream must be consumed");
        assert!(
            window[pipe_at..].contains("strip_ansi"),
            "the piped journal stream must be filtered before reaching the TTY: {}",
            &window[pipe_at..]
        );
    }

    /// Ordinary log lines must survive untouched — an over-broad filter that
    /// emptied the monitor would satisfy every assertion above.
    #[test]
    fn test_ordinary_lines_pass_through_intact() {
        let line = "2026-10-02T17:00:52 INFO DNS resolved via=cloudflare mss=88";
        assert_eq!(strip_ansi(line), line);
        let url = "DoH upstream cloudflare: post-quantum KEM handshake OK";
        assert_eq!(strip_ansi(url), url);
    }
}
