//! cname and https/svcb uncloaking defense (anti-tracker cloaking).
//!
//! extracts canonical name (cname) targets and rfc 9460 https/svcb aliasmode targets from upstream
//! dns responses, preventing tracking companies from bypassing adblockers by hiding behind first-party subdomains.

// extracts canonical cname targets and https/svcb aliasmode targets from answer section
pub fn extract_alias_targets(response_wire: &[u8]) -> Vec<String> {
    if response_wire.len() < 12 {
        return Vec::new();
    }

    let ancount = ((response_wire[6] as usize) << 8) | (response_wire[7] as usize);
    if ancount == 0 {
        return Vec::new();
    }

    let qdcount = ((response_wire[4] as usize) << 8) | (response_wire[5] as usize);
    let mut pos = 12;

    // skip question section
    for _ in 0..qdcount {
        pos = match skip_dns_name(response_wire, pos) {
            Some(p) => p,
            None => return Vec::new(),
        };
        pos += 4; // qtype (2) + qclass (2)
        if pos > response_wire.len() {
            return Vec::new();
        }
    }

    let mut targets = Vec::new();

    // iterate through answer records
    for _ in 0..ancount {
        pos = match skip_dns_name(response_wire, pos) {
            Some(p) => p,
            None => break,
        };

        if pos + 10 > response_wire.len() {
            break;
        }

        let rtype = ((response_wire[pos] as u16) << 8) | (response_wire[pos + 1] as u16);
        let rdlength = ((response_wire[pos + 8] as usize) << 8) | (response_wire[pos + 9] as usize);
        pos += 10;

        if pos + rdlength > response_wire.len() {
            break;
        }

        // rtype 5: CNAME record
        if rtype == 5 {
            if let Some((target, _)) = parse_dns_name(response_wire, pos) {
                if !target.is_empty() {
                    targets.push(target);
                }
            }
        } else if (rtype == 64 || rtype == 65) && rdlength >= 2 {
            // rtype 64: SVCB, rtype 65: HTTPS
            // in AliasMode, priority == 0, followed by target name in wire format
            let priority = ((response_wire[pos] as u16) << 8) | (response_wire[pos + 1] as u16);
            if priority == 0 && rdlength > 2 {
                if let Some((target, _)) = parse_dns_name(response_wire, pos + 2) {
                    if !target.is_empty() {
                        targets.push(target);
                    }
                }
            }
        }

        if targets.len() >= 64 {
            break;
        }

        pos += rdlength;
    }

    targets
}

// helper to skip compressed or uncompressed rfc 1035 labels
fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            return Some(pos + 2);
        }
        if (len & 0xC0) != 0 {
            return None; // invalid / reserved label format per RFC 1035
        }
        pos += 1 + len;
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
    None
}

// unpacks compressed dns name labels resolving RFC 1035 pointer offsets
fn parse_dns_name(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_pos = pos;
    let max_jumps = 10;
    let mut jumps = 0;

    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped {
                return_pos = pos + 1;
            }
            break;
        }

        // compression pointer marker (0b11xxxxxx)
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            if !jumped {
                return_pos = pos + 2;
                jumped = true;
            }
            jumps += 1;
            if jumps > max_jumps || pointer >= data.len() {
                return None;
            }
            pos = pointer;
            continue;
        }

        if (len & 0xC0) != 0 {
            return None; // invalid / reserved label format
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        let label_str = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        labels.push(label_str);
        if labels.len() >= 128 {
            return None;
        }
        pos += len;

        if !jumped {
            return_pos = pos;
        }
    }

    if labels.is_empty() {
        Some((String::new(), return_pos))
    } else {
        Some((labels.join("."), return_pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cname_target() {
        // synthesize a response with a CNAME record:
        // question: analytics.example.com
        // answer: analytics.example.com CNAME tracker.adtech.com
        let mut resp = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // Standard response
            0x00, 0x01, // 1 question
            0x00, 0x01, // 1 answer
            0x00, 0x00, 0x00, 0x00,
        ];

        // Question: analytics.example.com
        for label in ["analytics", "example", "com"] {
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0x00);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN

        // Answer RR: analytics.example.com (pointer to offset 12: 0xc00c)
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0x00, 0x05]); // Type CNAME (5)
        resp.extend_from_slice(&[0x00, 0x01]); // Class IN (1)
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL 300s

        // Target: tracker.adtech.com
        let mut rdata = Vec::new();
        for label in ["tracker", "adtech", "com"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0x00);

        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);

        let targets = extract_alias_targets(&resp);
        assert_eq!(targets, vec!["tracker.adtech.com"]);
    }

    #[test]
    fn test_extract_https_svcb_alias_target() {
        // synthesize response with HTTPS record (type 65) in AliasMode (priority 0)
        let mut resp = vec![
            0xAB, 0xCD, // ID
            0x81, 0x80, // Response
            0x00, 0x01, // 1 question
            0x00, 0x01, // 1 answer
            0x00, 0x00, 0x00, 0x00,
        ];

        // Question: example.com
        resp.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ]);
        resp.extend_from_slice(&[0x00, 0x41, 0x00, 0x01]); // Type HTTPS (65), Class IN (1)

        // Answer RR:
        resp.extend_from_slice(&[0xc0, 0x0c]); // pointer to example.com
        resp.extend_from_slice(&[0x00, 0x41]); // Type HTTPS (65)
        resp.extend_from_slice(&[0x00, 0x01]); // Class IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL 60s

        // RDATA: priority (0 = AliasMode) + Target Name "cdn.tracker.net"
        let mut rdata = vec![0x00, 0x00]; // Priority 0
        for label in ["cdn", "tracker", "net"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0x00);

        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);

        let targets = extract_alias_targets(&resp);
        assert_eq!(targets, vec!["cdn.tracker.net"]);
    }

    #[test]
    fn test_extract_alias_targets_empty_and_truncated() {
        assert!(extract_alias_targets(&[]).is_empty());
        assert!(extract_alias_targets(&[0x00; 10]).is_empty());

        // Header with ancount = 0
        let header_no_answers = [
            0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(extract_alias_targets(&header_no_answers).is_empty());
    }
}
