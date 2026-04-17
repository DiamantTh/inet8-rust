// SPDX-License-Identifier: GPL-3.0
//! IPv8 address types.
//!
//! An IPv8 address is a 64-bit value composed of a 32-bit Autonomous System
//! Number (ASN) and a 32-bit host identifier.  Both fields are carried in
//! big-endian byte order on the wire.
//!
//! Text format: `<asn>.<a>.<b>.<c>.<d>`  e.g. `64512.192.0.2.1`

#[cfg(feature = "kernel")]
use alloc::string::String;
#[cfg(feature = "kernel")]
use alloc::format;

use core::fmt;

// ---------------------------------------------------------------------------
// Ipv8Addr
// ---------------------------------------------------------------------------

/// A 64-bit IPv8 address consisting of an ASN and a 32-bit host identifier.
///
/// On the wire both fields are encoded in big-endian order.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv8Addr {
    pub asn: u32,
    pub host: u32,
}

impl Ipv8Addr {
    /// Create a new address from an ASN and a host identifier.
    pub const fn new(asn: u32, host: u32) -> Self {
        Self { asn, host }
    }

    /// Create an address from its eight individual bytes.
    ///
    /// Bytes 0-3 form the ASN (big-endian), bytes 4-7 form the host.
    pub fn from_bytes(b: [u8; 8]) -> Self {
        let asn = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let host = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        Self { asn, host }
    }

    /// Serialise the address to eight big-endian bytes.
    pub fn to_bytes(self) -> [u8; 8] {
        let a = self.asn.to_be_bytes();
        let h = self.host.to_be_bytes();
        [a[0], a[1], a[2], a[3], h[0], h[1], h[2], h[3]]
    }

    /// Return the four octets of the host portion.
    pub fn host_octets(self) -> [u8; 4] {
        self.host.to_be_bytes()
    }

    /// Parse an IPv8 address from its text representation.
    ///
    /// Format: `<asn>.<a>.<b>.<c>.<d>` where all components are decimal.
    ///
    /// Returns `None` if the string is malformed.
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.splitn(5, '.');
        let asn: u32 = parts.next()?.parse().ok()?;
        let a: u8 = parts.next()?.parse().ok()?;
        let b: u8 = parts.next()?.parse().ok()?;
        let c: u8 = parts.next()?.parse().ok()?;
        let d: u8 = parts.next()?.parse().ok()?;
        let host = u32::from_be_bytes([a, b, c, d]);
        Some(Self { asn, host })
    }
}

impl fmt::Display for Ipv8Addr {
    /// Format as `<asn>.<a>.<b>.<c>.<d>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.host_octets();
        write!(f, "{}.{}.{}.{}.{}", self.asn, a, b, c, d)
    }
}

// ---------------------------------------------------------------------------
// SockAddrIn8
// ---------------------------------------------------------------------------

/// Socket address structure for AF_INET8.
///
/// Analogous to `sockaddr_in` (IPv4) / `sockaddr_in6` (IPv6).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockAddrIn8 {
    /// Address family — must be `AF_INET8`.
    pub family: u16,
    /// Transport-layer port (big-endian on the wire).
    pub port: u16,
    /// Autonomous System Number.
    pub asn: u32,
    /// 32-bit host identifier.
    pub addr: u32,
}

impl SockAddrIn8 {
    /// Construct a new socket address.
    pub const fn new(family: u16, port: u16, asn: u32, addr: u32) -> Self {
        Self { family, port, asn, addr }
    }

    /// Extract the embedded [`Ipv8Addr`].
    pub fn ipv8_addr(&self) -> Ipv8Addr {
        Ipv8Addr { asn: self.asn, host: self.addr }
    }

    /// Serialise to sixteen big-endian bytes.
    ///
    /// Layout: family(2) | port(2) | asn(4) | addr(4) | pad(4)
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&self.family.to_be_bytes());
        buf[2..4].copy_from_slice(&self.port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.asn.to_be_bytes());
        buf[8..12].copy_from_slice(&self.addr.to_be_bytes());
        // bytes 12-15 reserved / padding
        buf
    }

    /// Deserialise from sixteen big-endian bytes.
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        let family = u16::from_be_bytes([b[0], b[1]]);
        let port = u16::from_be_bytes([b[2], b[3]]);
        let asn = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let addr = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        Self { family, port, asn, addr }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_display() {
        let a = Ipv8Addr::new(64512, u32::from_be_bytes([192, 0, 2, 1]));
        assert_eq!(a.to_string(), "64512.192.0.2.1");
    }

    #[test]
    fn addr_parse_roundtrip() {
        let original = "64512.192.0.2.1";
        let addr = Ipv8Addr::parse(original).expect("parse failed");
        assert_eq!(addr.asn, 64512);
        assert_eq!(addr.host_octets(), [192, 0, 2, 1]);
        assert_eq!(addr.to_string(), original);
    }

    #[test]
    fn addr_parse_invalid() {
        assert!(Ipv8Addr::parse("").is_none());
        assert!(Ipv8Addr::parse("64512.999.0.0.0").is_none()); // octet out of range
        assert!(Ipv8Addr::parse("abc.1.2.3.4").is_none());
        assert!(Ipv8Addr::parse("64512.1.2.3").is_none()); // too few parts
    }

    #[test]
    fn addr_bytes_roundtrip() {
        let addr = Ipv8Addr::new(12345, 0x0a000001);
        let bytes = addr.to_bytes();
        let back = Ipv8Addr::from_bytes(bytes);
        assert_eq!(addr, back);
    }

    #[test]
    fn sockaddr_bytes_roundtrip() {
        use crate::AF_INET8;
        let sa = SockAddrIn8::new(AF_INET8, 8080, 64512, 0xc0000201);
        let bytes = sa.to_bytes();
        let back = SockAddrIn8::from_bytes(&bytes);
        assert_eq!(sa, back);
    }

    #[test]
    fn sockaddr_ipv8_addr() {
        let sa = SockAddrIn8::new(0, 0, 10, 20);
        let addr = sa.ipv8_addr();
        assert_eq!(addr.asn, 10);
        assert_eq!(addr.host, 20);
    }
}
