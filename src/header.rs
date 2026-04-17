// SPDX-License-Identifier: GPL-3.0
//! IPv8 on-wire packet header.
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    version    |   protocol    |         payload_len           |
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
//! Total: 20 bytes.  All multi-byte fields are big-endian.

/// Size of the fixed IPv8 header in bytes.
pub const HEADER_LEN: usize = 20;

/// Version number that MUST appear in the `version` field.
pub const VERSION: u8 = 1;

/// IPv8 packet header.
///
/// All fields use big-endian representation on the wire.
/// The `#[repr(C)]` attribute ensures field ordering matches the wire format
/// so that the struct can be used directly in kernel `sk_buff` manipulation.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv8Header {
    /// Must be [`VERSION`] (= 1).
    pub version: u8,
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
    pub const fn new(
        protocol: u8,
        payload_len: u16,
        src_asn: u32,
        src_host: u32,
        dst_asn: u32,
        dst_host: u32,
    ) -> Self {
        Self {
            version: VERSION,
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
    pub fn validate(&self, payload: &[u8]) -> Result<(), &'static str> {
        if self.version != VERSION {
            return Err("invalid version");
        }
        if self.payload_len as usize != payload.len() {
            return Err("payload_len mismatch");
        }
        Ok(())
    }

    /// Serialise the header to a 20-byte big-endian buffer.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = self.version;
        buf[1] = self.protocol;
        buf[2..4].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[4..8].copy_from_slice(&self.src_asn.to_be_bytes());
        buf[8..12].copy_from_slice(&self.src_host.to_be_bytes());
        buf[12..16].copy_from_slice(&self.dst_asn.to_be_bytes());
        buf[16..20].copy_from_slice(&self.dst_host.to_be_bytes());
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
            protocol: bytes[1],
            payload_len: u16::from_be_bytes([bytes[2], bytes[3]]),
            src_asn: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            src_host: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            dst_asn: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            dst_host: u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> Ipv8Header {
        Ipv8Header::new(17, 8, 64512, 0xc0000201, 64513, 0xc0000202)
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
    fn header_big_endian_fields() {
        let hdr = Ipv8Header::new(6, 100, 0x0001_0002, 0x0003_0004, 0x0005_0006, 0x0007_0008);
        let b = hdr.to_bytes();
        // src_asn starts at byte 4
        assert_eq!(&b[4..8], &[0x00, 0x01, 0x00, 0x02]);
        // dst_asn starts at byte 12
        assert_eq!(&b[12..16], &[0x00, 0x05, 0x00, 0x06]);
        // payload_len at bytes 2-3
        assert_eq!(&b[2..4], &[0x00, 0x64]);
    }

    #[test]
    fn header_from_bytes_too_short() {
        assert!(Ipv8Header::from_bytes(&[0u8; 19]).is_none());
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
        let hdr = Ipv8Header::new(17, 8, 1, 1, 2, 2);
        assert!(hdr.validate(&payload).is_ok());
    }

    #[test]
    fn header_validate_wrong_version() {
        let payload = [0u8; 8];
        let mut hdr = Ipv8Header::new(17, 8, 1, 1, 2, 2);
        hdr.version = 0;
        assert!(hdr.validate(&payload).is_err());
    }

    #[test]
    fn header_validate_payload_mismatch() {
        let payload = [0u8; 4]; // 4 bytes, but header says 8
        let hdr = Ipv8Header::new(17, 8, 1, 1, 2, 2);
        assert!(hdr.validate(&payload).is_err());
    }

    #[test]
    fn header_payload_slice() {
        let hdr = Ipv8Header::new(17, 4, 1, 1, 2, 2);
        let mut packet = [0u8; HEADER_LEN + 4];
        packet[..HEADER_LEN].copy_from_slice(&hdr.to_bytes());
        packet[HEADER_LEN..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let p = hdr.payload(&packet).expect("payload extraction failed");
        assert_eq!(p, &[0xde, 0xad, 0xbe, 0xef]);
    }
}
