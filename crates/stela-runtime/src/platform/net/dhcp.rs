//! The DHCPv4 message a raw Ethernet frame carries, for the boot log's
//! progress lines while the stack waits for a lease. Only the message type
//! is read: no address, name or option value leaves this module.

/// The UDP ports of a DHCPv4 server and client (RFC 2131).
const SERVER: u16 = 67;
const CLIENT: u16 = 68;
/// The magic cookie that starts the options (RFC 2131 section 3).
const COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// The DHCP Message Type option (RFC 2132 section 9.6).
const MESSAGE_TYPE: u8 = 53;

/// The DHCPv4 message type `frame` carries, an Ethernet II frame without its
/// FCS, or `None` for any other frame.
pub fn message(frame: &[u8]) -> Option<&'static str> {
    if frame.get(12..14)? != [0x08, 0x00] {
        return None;
    }
    let ip = frame.get(14..)?;
    let header = usize::from(ip.first()? & 0x0f) * 4;
    // IPv4, UDP, and the first fragment.
    if ip[0] >> 4 != 4
        || header < 20
        || *ip.get(9)? != 17
        || u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]) & 0x1fff != 0
    {
        return None;
    }
    let udp = ip.get(header..)?;
    let source = u16::from_be_bytes([*udp.first()?, *udp.get(1)?]);
    let destination = u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]);
    if !matches!((source, destination), (CLIENT, SERVER) | (SERVER, CLIENT)) {
        return None;
    }
    let bootp = udp.get(8..)?;
    if bootp.get(236..240)? != COOKIE {
        return None;
    }
    let mut options = bootp.get(240..)?;
    while let Some((&code, rest)) = options.split_first() {
        match code {
            0 => options = rest,
            255 => return None,
            _ => {
                let (&length, rest) = rest.split_first()?;
                let value = rest.get(..usize::from(length))?;
                if code == MESSAGE_TYPE {
                    return Some(match value.first()? {
                        1 => "DISCOVER",
                        2 => "OFFER",
                        3 => "REQUEST",
                        4 => "DECLINE",
                        5 => "ACK",
                        6 => "NAK",
                        7 => "RELEASE",
                        8 => "INFORM",
                        _ => "message of an unknown type",
                    });
                }
                options = &rest[usize::from(length)..];
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn frame(source: u16, destination: u16, options: &[u8]) -> Vec<u8> {
        let mut frame = alloc::vec![0; 14];
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        let mut ip = alloc::vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17];
        ip.resize(20, 0);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&source.to_be_bytes());
        frame.extend_from_slice(&destination.to_be_bytes());
        frame.extend_from_slice(&[0; 4]);
        let mut bootp = alloc::vec![0; 236];
        bootp[0] = 1;
        bootp.extend_from_slice(&COOKIE);
        bootp.extend_from_slice(options);
        frame.extend_from_slice(&bootp);
        frame
    }

    #[test]
    fn each_dhcp_message_type_is_named_and_other_frames_are_not() {
        assert_eq!(
            message(&frame(68, 67, &[0, 53, 1, 1, 255])),
            Some("DISCOVER")
        );
        // Another option before the type is skipped.
        assert_eq!(
            message(&frame(67, 68, &[61, 2, 9, 9, 53, 1, 5, 255])),
            Some("ACK")
        );
        assert_eq!(message(&frame(67, 68, &[53, 1, 6])), Some("NAK"));
        // No type, other ports, a truncated option or another protocol.
        assert_eq!(message(&frame(68, 67, &[255])), None);
        assert_eq!(message(&frame(1000, 67, &[53, 1, 1])), None);
        assert_eq!(message(&frame(68, 67, &[53, 4, 1])), None);
        let mut arp = frame(68, 67, &[53, 1, 1]);
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(message(&arp), None);
        assert_eq!(message(&arp[..10]), None);
        // A later fragment carries no UDP header.
        let mut fragment = frame(68, 67, &[53, 1, 1]);
        fragment[14 + 7] = 1;
        assert_eq!(message(&fragment), None);
    }
}
