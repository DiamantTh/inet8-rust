// SPDX-License-Identifier: GPL-3.0
//! IPv8 on-wire packet header.
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    version    |   hop_limit   |    protocol   |   (reserved)  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           payload_len         |          (reserved)           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           src_asn                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          src_host                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           dst_asn                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          dst_host                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Total: 24 bytes.  All multi-byte fields are big-endian.
//! Reserved bytes must be transmitted as zero and ignored on receipt.

/// Size of the fixed IPv8 header in bytes.
///
/// Layout (24 bytes, all multi-byte fields big-endian):
/// ```text
/// byte  0: version
/// byte  1: hop_limit
/// byte  2: protocol
/// byte  3: reserved (must be 0)
/// bytes 4–5: payload_len
/// bytes 6–7: reserved (must be 0)
/// bytes 8–11:  src_asn
/// bytes 12–15: src_host
/// bytes 16–19: dst_asn
/// bytes 20–23: dst_host
/// ```
pub const HEADER_LEN: usize = 24;

/// Version number that MUST appear in the `version` field.
pub const VERSION: u8 = 1;

/// Default hop limit applied to outgoing packets.
///
/// Mirrors the conventional starting value used by IPv4 (TTL = 64) and
/// IPv6 (Hop Limit = 64).  A router decrements this field before forwarding;
/// when it reaches zero the packet is discarded to prevent routing loops.
pub const DEFAULT_HOP_LIMIT: u8 = 64;

/// IPv8 packet header.
///
/// All multi-byte fields use big-endian representation on the wire.
/// The `#[repr(C)]` attribute ensures field ordering matches the wire format
/// so that the struct can be used directly in kernel `sk_buff` manipulation.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv8Header {
    /// Must be [`VERSION`] (= 1).
    pub version: u8,
    /// Decremented by each forwarding router.  Packet is dropped when this
    /// reaches zero, preventing routing loops (analogous to IPv4 TTL /
    /// IPv6 Hop Limit).
    pub hop_limit: u8,
    /// Higher-layer protocol identifier (e.g. TCP = 6, UDP = 17).
    pub protocol: u8,
    /// Length of the payload that follows this header, in bytes.
    pub payload_len: u16,
    /// Source Autonomous System Number.
    pub src_asn: u32,
    /// Source host identifier.
    pub src_host: u32,
    /// Destination Autonomous System Number.
    pub dst_asn: u32,
    /// Destination host identifier.
    pub dst_host: u32,
}

impl Ipv8Header {
    /// Construct a new header.
    ///
    /// `version` is automatically set to [`VERSION`].
    /// Use [`DEFAULT_HOP_LIMIT`] for `hop_limit` unless the application
    /// requires a different value.
    pub const fn new(
        protocol: u8,
        hop_limit: u8,
        payload_len: u16,
        src_asn: u32,
        src_host: u32,
        dst_asn: u32,
        dst_host: u32,
    ) -> Self {
        Self {
            version: VERSION,
            hop_limit,
            protocol,
            payload_len,
            src_asn,
            src_host,
            dst_asn,
            dst_host,
        }
    }

    /// Validate the header fields.
    ///
    /// Returns `Err` with a human-readable description if any constraint is
    /// violated.  The `payload` slice is used to verify that `payload_len`
    /// matches the actual data length.
    ///
    /// Validation rules (parallel to inet4/inet6 receive-path checks):
    /// * `version` must be [`VERSION`]
    /// * `hop_limit` must be non-zero (a zero hop-limit means the packet has
    ///   expired and must be dropped to prevent routing loops)
    /// * `payload_len` must match the length of the supplied payload slice
    /// * source address must not be the unspecified address (all-zeros)
    /// * destination address must not be the unspecified address (all-zeros)
    pub fn validate(&self, payload: &[u8]) -> Result<(), &'static str> {
        if self.version != VERSION {
            return Err("invalid version");
        }
        if self.hop_limit == 0 {
            return Err("hop_limit expired");
        }
        if self.payload_len as usize != payload.len() {
            return Err("payload_len mismatch");
        }
        if self.src_asn == 0 && self.src_host == 0 {
            return Err("unspecified source address");
        }
        if self.dst_asn == 0 && self.dst_host == 0 {
            return Err("unspecified destination address");
        }
        Ok(())
    }

    /// Serialise the header to a 24-byte big-endian buffer.
    ///
    /// Wire layout:
    /// * byte  0   – version
    /// * byte  1   – hop_limit
    /// * byte  2   – protocol
    /// * byte  3   – reserved (always 0)
    /// * bytes 4–5 – payload_len
    /// * bytes 6–7 – reserved (always 0)
    /// * bytes 8–11  – src_asn
    /// * bytes 12–15 – src_host
    /// * bytes 16–19 – dst_asn
    /// * bytes 20–23 – dst_host
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = self.version;
        buf[1] = self.hop_limit;
        buf[2] = self.protocol;
        // buf[3] reserved – remains 0
        buf[4..6].copy_from_slice(&self.payload_len.to_be_bytes());
        // buf[6..8] reserved – remain 0
        buf[8..12].copy_from_slice(&self.src_asn.to_be_bytes());
        buf[12..16].copy_from_slice(&self.src_host.to_be_bytes());
        buf[16..20].copy_from_slice(&self.dst_asn.to_be_bytes());
        buf[20..24].copy_from_slice(&self.dst_host.to_be_bytes());
        buf
    }

    /// Parse a header from raw bytes.
    ///
    /// Returns `None` when:
    /// * the slice is shorter than [`HEADER_LEN`], or
    /// * the `version` field is not [`VERSION`].
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let version = bytes[0];
        if version != VERSION {
            return None;
        }
        Some(Self {
            version,
            hop_limit: bytes[1],
            protocol: bytes[2],
            // bytes[3] reserved
            payload_len: u16::from_be_bytes([bytes[4], bytes[5]]),
            // bytes[6..8] reserved
            src_asn:  u32::from_be_bytes([bytes[8],  bytes[9],  bytes[10], bytes[11]]),
            src_host: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            dst_asn:  u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            dst_host: u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
        })
    }

    /// Return a reference to the payload slice that follows this header.
    ///
    /// The `packet` slice must include the header bytes.  Returns `None` when
    /// bounds are not satisfied or `payload_len` does not match.
    pub fn payload<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        let payload = packet.get(HEADER_LEN..)?;
        if payload.len() != self.payload_len as usize {
            return None;
        }
        Some(payload)
    }

    /// Decrement the hop limit by one and return the updated header.
    ///
    /// Returns `None` when the hop limit is already zero or would reach zero
    /// after the decrement; in that case the packet must be discarded.
    /// This mirrors what a forwarding router does before re-transmitting a
    /// packet (analogous to IPv4 TTL decrement / IPv6 Hop Limit decrement).
    #[must_use]
    pub fn decrement_hop_limit(self) -> Option<Self> {
        let new_limit = self.hop_limit.checked_sub(1).filter(|&v| v > 0)?;
        Some(Self { hop_limit: new_limit, ..self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> Ipv8Header {
        Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 8, 64512, 0xc0000201, 64513, 0xc0000202)
    }

    #[test]
    fn header_serialise_deserialise() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);

        let back = Ipv8Header::from_bytes(&bytes).expect("deserialise failed");
        assert_eq!(hdr, back);
    }

    #[test]
    fn header_version_field() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes[0], VERSION);
    }

    #[test]
    fn header_hop_limit_field() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes[1], DEFAULT_HOP_LIMIT);
    }

    #[test]
    fn header_big_endian_fields() {
        let hdr = Ipv8Header::new(6, DEFAULT_HOP_LIMIT, 100, 0x0001_0002, 0x0003_0004, 0x0005_0006, 0x0007_0008);
        let b = hdr.to_bytes();
        // hop_limit at byte 1
        assert_eq!(b[1], DEFAULT_HOP_LIMIT);
        // protocol at byte 2
        assert_eq!(b[2], 6);
        // payload_len at bytes 4-5
        assert_eq!(&b[4..6], &[0x00, 0x64]);
        // src_asn starts at byte 8
        assert_eq!(&b[8..12], &[0x00, 0x01, 0x00, 0x02]);
        // dst_asn starts at byte 16
        assert_eq!(&b[16..20], &[0x00, 0x05, 0x00, 0x06]);
    }

    #[test]
    fn header_reserved_bytes_are_zero() {
        let hdr = make_header();
        let b = hdr.to_bytes();
        assert_eq!(b[3], 0, "reserved byte 3 must be 0");
        assert_eq!(b[6], 0, "reserved byte 6 must be 0");
        assert_eq!(b[7], 0, "reserved byte 7 must be 0");
    }

    #[test]
    fn header_from_bytes_too_short() {
        assert!(Ipv8Header::from_bytes(&[0u8; 23]).is_none());
    }

    #[test]
    fn header_from_bytes_wrong_version() {
        let mut b = [0u8; HEADER_LEN];
        b[0] = 2; // wrong version
        assert!(Ipv8Header::from_bytes(&b).is_none());
    }

    #[test]
    fn header_validate_ok() {
        let payload = [0u8; 8];
        let hdr = Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 8, 1, 1, 2, 2);
        assert!(hdr.validate(&payload).is_ok());
    }

    #[test]
    fn header_validate_wrong_version() {
        let payload = [0u8; 8];
        let mut hdr = Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 8, 1, 1, 2, 2);
        hdr.version = 0;
        assert!(hdr.validate(&payload).is_err());
    }

    #[test]
    fn header_validate_hop_limit_zero() {
        let payload = [0u8; 8];
        let mut hdr = Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 8, 1, 1, 2, 2);
        hdr.hop_limit = 0;
        assert_eq!(hdr.validate(&payload), Err("hop_limit expired"));
    }

    #[test]
    fn header_validate_payload_mismatch() {
        let payload = [0u8; 4]; // 4 bytes, but header says 8
        let hdr = Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 8, 1, 1, 2, 2);
        assert!(hdr.validate(&payload).is_err());
    }

    #[test]
    fn header_validate_unspecified_src() {
        let payload = [0u8; 4];
        let hdr = Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 4, 0, 0, 2, 2);
        assert_eq!(hdr.validate(&payload), Err("unspecified source address"));
    }

    #[test]
    fn header_validate_unspecified_dst() {
        let payload = [0u8; 4];
        let hdr = Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 4, 1, 1, 0, 0);
        assert_eq!(hdr.validate(&payload), Err("unspecified destination address"));
    }

    #[test]
    fn header_payload_slice() {
        let hdr = Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 4, 1, 1, 2, 2);
        let mut packet = [0u8; HEADER_LEN + 4];
        packet[..HEADER_LEN].copy_from_slice(&hdr.to_bytes());
        packet[HEADER_LEN..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let p = hdr.payload(&packet).expect("payload extraction failed");
        assert_eq!(p, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn header_decrement_hop_limit_normal() {
        let hdr = Ipv8Header::new(17, 10, 0, 1, 1, 2, 2);
        let decremented = hdr.decrement_hop_limit().expect("should not expire");
        assert_eq!(decremented.hop_limit, 9);
    }

    #[test]
    fn header_decrement_hop_limit_last() {
        // Decrementing from 1 would reach 0 → must be dropped.
        let hdr = Ipv8Header::new(17, 1, 0, 1, 1, 2, 2);
        assert!(hdr.decrement_hop_limit().is_none());
    }

    #[test]
    fn header_decrement_hop_limit_already_zero() {
        let mut hdr = Ipv8Header::new(17, DEFAULT_HOP_LIMIT, 0, 1, 1, 2, 2);
        hdr.hop_limit = 0;
        assert!(hdr.decrement_hop_limit().is_none());
    }
}
