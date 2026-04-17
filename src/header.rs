// SPDX-License-Identifier: GPL-3.0
//! IPv8 on-wire packet header (28 bytes).
//!
//! Based on [draft-thain-ipv8-00](https://www.ietf.org/archive/id/draft-thain-ipv8-00.html).
//! The format extends the IPv4 header by replacing the 32-bit source and
//! destination address fields with 64-bit IPv8 address fields, giving a fixed
//! header of 28 bytes (IHL = 7).
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  ver_ihl=0x87 |   dscp_ecn    |          total_len            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           identification      |        flags_frag             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      ttl      |   protocol    |         header checksum       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        source ASN                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       source host                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     destination ASN                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     destination host                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Total: 28 bytes.  All multi-byte fields are big-endian.

/// IPv8 version number: 8 (as in "IPv**8**").
///
/// Stored in the upper four bits of `ver_ihl` on the wire.
pub const VERSION: u8 = 8;

/// Internet Header Length in 32-bit words: 28 / 4 = 7.
///
/// Stored in the lower four bits of `ver_ihl` on the wire.
pub const IHL: u8 = 7;

/// Combined `ver_ihl` byte value: version 8 in upper nibble, IHL 7 in lower.
///
/// On the wire this is always `0x87`.
pub const VER_IHL: u8 = (VERSION << 4) | IHL;

/// Size of the fixed IPv8 header in bytes (`IHL × 4 = 28`).
pub const HEADER_LEN: usize = 28;

/// Default TTL (Time to Live / Hop Limit) for outgoing packets.
///
/// Matches the conventional default used by IPv4 and IPv6.  Each forwarding
/// router decrements this field; when it reaches zero the packet is discarded
/// to prevent routing loops.
pub const DEFAULT_TTL: u8 = 64;

/// "Don't Fragment" flag in the `flags_frag` field (bit 14).
///
/// When set, routers must not fragment the packet.  Use this for IPv8 packets
/// that should travel end-to-end without being split.
pub const FLAG_DF: u16 = 0x4000;

/// IPv8 packet header (28 bytes, as per draft-thain-ipv8-00).
///
/// All multi-byte fields use **big-endian** byte order on the wire.
/// The `checksum` field is computed by [`Ipv8Header::to_bytes`] and verified
/// by [`Ipv8Header::from_bytes`]; it is not stored in this struct.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv8Header {
    /// Differentiated Services Code Point (6 bits) + ECN (2 bits).
    /// Analogous to the IPv4 ToS / DSCP+ECN byte.
    pub dscp_ecn: u8,
    /// Fragmentation identification field.
    pub ident: u16,
    /// Flags (3 bits) + Fragment offset (13 bits).
    /// Set [`FLAG_DF`] to prevent fragmentation.
    pub flags_frag: u16,
    /// Time to Live — decremented by each forwarding router.
    /// Packet is discarded when this reaches zero.
    pub ttl: u8,
    /// Higher-layer protocol identifier (e.g. TCP = 6, UDP = 17).
    pub protocol: u8,
    /// Length of the payload that follows this header, in bytes.
    /// On the wire this is stored as `total_len = HEADER_LEN + payload_len`.
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
    /// Construct a new header with sensible defaults for optional fields.
    ///
    /// * `ver_ihl` is always set to [`VER_IHL`] (= `0x87`).
    /// * `dscp_ecn` defaults to 0 (best-effort, no ECN).
    /// * `ident` defaults to 0.
    /// * `flags_frag` defaults to [`FLAG_DF`] (don't fragment).
    /// * Use [`DEFAULT_TTL`] for `ttl` unless the application requires a
    ///   different value.
    pub const fn new(
        protocol: u8,
        ttl: u8,
        payload_len: u16,
        src_asn: u32,
        src_host: u32,
        dst_asn: u32,
        dst_host: u32,
    ) -> Self {
        Self {
            dscp_ecn: 0,
            ident: 0,
            flags_frag: FLAG_DF,
            ttl,
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
    /// Note: when a header is obtained via [`Ipv8Header::from_bytes`] the
    /// checksum has already been verified.  This method performs the remaining
    /// semantic checks:
    /// * `ttl` must be non-zero (a zero TTL means the packet has expired and
    ///   must be dropped to prevent routing loops)
    /// * `payload_len` must match the length of the supplied payload slice
    /// * source address must not be the unspecified address (all-zeros)
    /// * destination address must not be the unspecified address (all-zeros)
    pub fn validate(&self, payload: &[u8]) -> Result<(), &'static str> {
        if self.ttl == 0 {
            return Err("ttl expired");
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

    /// Serialise the header to a 28-byte big-endian buffer.
    ///
    /// The header checksum is computed over the 28 header bytes (with the
    /// checksum field initialised to zero) and written to bytes 10–11,
    /// matching the internet checksum algorithm specified in RFC 1071.
    ///
    /// Wire layout:
    /// * byte  0      – `ver_ihl` (always `0x87`: version 8, IHL 7)
    /// * byte  1      – `dscp_ecn`
    /// * bytes 2–3    – `total_len` (= `HEADER_LEN + payload_len`)
    /// * bytes 4–5    – `ident`
    /// * bytes 6–7    – `flags_frag`
    /// * byte  8      – `ttl`
    /// * byte  9      – `protocol`
    /// * bytes 10–11  – header checksum (internet checksum over bytes 0–27)
    /// * bytes 12–15  – `src_asn`
    /// * bytes 16–19  – `src_host`
    /// * bytes 20–23  – `dst_asn`
    /// * bytes 24–27  – `dst_host`
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let total_len = HEADER_LEN as u16 + self.payload_len;
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = VER_IHL;
        buf[1] = self.dscp_ecn;
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        buf[4..6].copy_from_slice(&self.ident.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags_frag.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        // bytes 10–11 are the checksum; leave as 0 for now
        buf[12..16].copy_from_slice(&self.src_asn.to_be_bytes());
        buf[16..20].copy_from_slice(&self.src_host.to_be_bytes());
        buf[20..24].copy_from_slice(&self.dst_asn.to_be_bytes());
        buf[24..28].copy_from_slice(&self.dst_host.to_be_bytes());
        // Compute and insert the internet checksum
        let ck = ipv8_checksum(&buf);
        buf[10..12].copy_from_slice(&ck.to_be_bytes());
        buf
    }

    /// Parse a header from raw bytes.
    ///
    /// Returns `None` when:
    /// * the slice is shorter than [`HEADER_LEN`] (28 bytes),
    /// * the `ver_ihl` field does not encode version 8 with IHL ≥ 7, or
    /// * the internet checksum over the 28 header bytes is non-zero
    ///   (indicating bit errors or a truncated/corrupted packet).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let ver_ihl = bytes[0];
        let version = (ver_ihl >> 4) & 0x0F;
        let ihl     = ver_ihl & 0x0F;
        if version != VERSION || ihl < IHL {
            return None;
        }
        // Verify internet checksum: summing all 16-bit words over the header
        // (including the stored checksum) must produce zero.
        if ipv8_checksum(&bytes[..HEADER_LEN]) != 0 {
            return None;
        }
        let total_len   = u16::from_be_bytes([bytes[2],  bytes[3]]);
        // Use saturating_sub to handle malformed packets where total_len < HEADER_LEN
        // (which would underflow if computed with plain subtraction).
        let payload_len = total_len.saturating_sub(HEADER_LEN as u16);
        Some(Self {
            dscp_ecn:   bytes[1],
            ident:      u16::from_be_bytes([bytes[4],  bytes[5]]),
            flags_frag: u16::from_be_bytes([bytes[6],  bytes[7]]),
            ttl:        bytes[8],
            protocol:   bytes[9],
            payload_len,
            src_asn:  u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            src_host: u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            dst_asn:  u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            dst_host: u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
        })
    }

    /// Return a reference to the payload slice that follows this header.
    ///
    /// The `packet` slice must include the full header bytes.  Returns `None`
    /// when bounds are not satisfied or `payload_len` does not match the
    /// actual bytes available after the header.
    pub fn payload<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        let payload = packet.get(HEADER_LEN..)?;
        if payload.len() != self.payload_len as usize {
            return None;
        }
        Some(payload)
    }

    /// Decrement the TTL by one and return the updated header.
    ///
    /// Returns `None` when the TTL is already zero or would reach zero after
    /// the decrement; in that case the packet must be discarded.
    /// This is the operation performed by every forwarding router before
    /// re-transmitting a packet (analogous to IPv4 TTL / IPv6 Hop Limit).
    #[must_use]
    pub fn decrement_ttl(self) -> Option<Self> {
        let new_ttl = self.ttl.checked_sub(1).filter(|&v| v != 0)?;
        Some(Self { ttl: new_ttl, ..self })
    }
}

// ---------------------------------------------------------------------------
// Internet checksum (RFC 1071)
// ---------------------------------------------------------------------------

/// Compute the internet checksum over `data`.
///
/// Sums all 16-bit big-endian words, folds carries, and returns the
/// one's-complement result.  When used for verification, computing the
/// checksum over a full header (including the stored checksum field) must
/// yield zero.
pub fn ipv8_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        // Odd byte: pad with a zero byte on the right.
        sum += (data[i] as u32) << 8;
    }
    // Fold 32-bit sum into 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> Ipv8Header {
        Ipv8Header::new(17, DEFAULT_TTL, 8, 64512, 0xc0000201, 64513, 0xc0000202)
    }

    // -- checksum ------------------------------------------------------------

    #[test]
    fn checksum_all_zeros() {
        // Over an all-zero 28-byte buffer the checksum must be 0xFFFF.
        let buf = [0u8; HEADER_LEN];
        assert_eq!(ipv8_checksum(&buf), 0xFFFF);
    }

    #[test]
    fn checksum_roundtrip() {
        // Computing the checksum over a buffer that already contains a valid
        // checksum must return 0 (internet-checksum verification property).
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(ipv8_checksum(&bytes), 0, "checksum verification must return 0");
    }

    // -- to_bytes / from_bytes -----------------------------------------------

    #[test]
    fn header_serialise_deserialise() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), HEADER_LEN);
        let back = Ipv8Header::from_bytes(&bytes).expect("deserialise failed");
        assert_eq!(hdr, back);
    }

    #[test]
    fn header_ver_ihl_field() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes[0], VER_IHL, "byte 0 must be 0x87 (version 8, IHL 7)");
        assert_eq!(bytes[0], 0x87);
    }

    #[test]
    fn header_ttl_field() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes[8], DEFAULT_TTL, "ttl must be at byte 8");
    }

    #[test]
    fn header_protocol_field() {
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(bytes[9], 17, "protocol must be at byte 9");
    }

    #[test]
    fn header_total_len_field() {
        // payload_len = 8, so total_len = 28 + 8 = 36 = 0x0024
        let hdr = make_header();
        let bytes = hdr.to_bytes();
        assert_eq!(&bytes[2..4], &[0x00, 0x24], "total_len must be at bytes 2-3");
    }

    #[test]
    fn header_big_endian_fields() {
        let hdr = Ipv8Header::new(6, DEFAULT_TTL, 100, 0x0001_0002, 0x0003_0004, 0x0005_0006, 0x0007_0008);
        let b = hdr.to_bytes();
        // ver_ihl at byte 0
        assert_eq!(b[0], 0x87);
        // ttl at byte 8
        assert_eq!(b[8], DEFAULT_TTL);
        // protocol at byte 9
        assert_eq!(b[9], 6);
        // total_len at bytes 2-3: 28 + 100 = 128 = 0x0080
        assert_eq!(&b[2..4], &[0x00, 0x80]);
        // src_asn starts at byte 12
        assert_eq!(&b[12..16], &[0x00, 0x01, 0x00, 0x02]);
        // src_host starts at byte 16
        assert_eq!(&b[16..20], &[0x00, 0x03, 0x00, 0x04]);
        // dst_asn starts at byte 20
        assert_eq!(&b[20..24], &[0x00, 0x05, 0x00, 0x06]);
        // dst_host starts at byte 24
        assert_eq!(&b[24..28], &[0x00, 0x07, 0x00, 0x08]);
    }

    #[test]
    fn header_from_bytes_too_short() {
        assert!(Ipv8Header::from_bytes(&[0u8; HEADER_LEN - 1]).is_none());
    }

    #[test]
    fn header_from_bytes_wrong_version() {
        // Build a valid packet then corrupt the version nibble.
        let hdr = make_header();
        let mut b = hdr.to_bytes();
        // Set version to 1 (wrong), keeping IHL = 7.
        b[0] = (1u8 << 4) | IHL;
        assert!(Ipv8Header::from_bytes(&b).is_none());
    }

    #[test]
    fn header_from_bytes_bad_checksum() {
        let hdr = make_header();
        let mut b = hdr.to_bytes();
        // Corrupt one byte to invalidate the checksum.
        b[12] ^= 0xFF;
        assert!(Ipv8Header::from_bytes(&b).is_none());
    }

    // -- validate ------------------------------------------------------------

    #[test]
    fn header_validate_ok() {
        let payload = [0u8; 8];
        let hdr = Ipv8Header::new(17, DEFAULT_TTL, 8, 1, 1, 2, 2);
        assert!(hdr.validate(&payload).is_ok());
    }

    #[test]
    fn header_validate_ttl_zero() {
        let payload = [0u8; 8];
        let mut hdr = Ipv8Header::new(17, DEFAULT_TTL, 8, 1, 1, 2, 2);
        hdr.ttl = 0;
        assert_eq!(hdr.validate(&payload), Err("ttl expired"));
    }

    #[test]
    fn header_validate_payload_mismatch() {
        let payload = [0u8; 4]; // 4 bytes, but header says 8
        let hdr = Ipv8Header::new(17, DEFAULT_TTL, 8, 1, 1, 2, 2);
        assert!(hdr.validate(&payload).is_err());
    }

    #[test]
    fn header_validate_unspecified_src() {
        let payload = [0u8; 4];
        let hdr = Ipv8Header::new(17, DEFAULT_TTL, 4, 0, 0, 2, 2);
        assert_eq!(hdr.validate(&payload), Err("unspecified source address"));
    }

    #[test]
    fn header_validate_unspecified_dst() {
        let payload = [0u8; 4];
        let hdr = Ipv8Header::new(17, DEFAULT_TTL, 4, 1, 1, 0, 0);
        assert_eq!(hdr.validate(&payload), Err("unspecified destination address"));
    }

    // -- payload -------------------------------------------------------------

    #[test]
    fn header_payload_slice() {
        let hdr = Ipv8Header::new(17, DEFAULT_TTL, 4, 1, 1, 2, 2);
        let mut packet = [0u8; HEADER_LEN + 4];
        packet[..HEADER_LEN].copy_from_slice(&hdr.to_bytes());
        packet[HEADER_LEN..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let p = hdr.payload(&packet).expect("payload extraction failed");
        assert_eq!(p, &[0xde, 0xad, 0xbe, 0xef]);
    }

    // -- decrement_ttl -------------------------------------------------------

    #[test]
    fn header_decrement_ttl_normal() {
        let hdr = Ipv8Header::new(17, 10, 0, 1, 1, 2, 2);
        let dec = hdr.decrement_ttl().expect("should not expire");
        assert_eq!(dec.ttl, 9);
    }

    #[test]
    fn header_decrement_ttl_last() {
        // Decrementing from 1 reaches 0 → packet must be dropped (None).
        let hdr = Ipv8Header::new(17, 1, 0, 1, 1, 2, 2);
        assert!(hdr.decrement_ttl().is_none());
    }

    #[test]
    fn header_decrement_ttl_already_zero() {
        let mut hdr = Ipv8Header::new(17, DEFAULT_TTL, 0, 1, 1, 2, 2);
        hdr.ttl = 0;
        assert!(hdr.decrement_ttl().is_none());
    }
}
