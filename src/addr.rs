// SPDX-License-Identifier: GPL-3.0
//! IPv8 address types.
//!
//! An IPv8 address is a 64-bit value composed of a 32-bit Autonomous System
//! Number (ASN) routing prefix and a 32-bit host identifier.  Both fields are
//! carried in big-endian byte order on the wire.
//!
//! Canonical text format (8-octet): `r.r.r.r.n.n.n.n`
//! e.g. `0.0.251.240.10.0.1.1` (ASN 64496, host 10.0.1.1)
//!
//! ASN dot-notation is also accepted for input: `64496.10.0.1.1`

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv8Addr {
    pub asn: u32,
    pub host: u32,
}

impl Ipv8Addr {
    /// The unspecified IPv8 address `0.0.0.0.0.0.0.0` (all zeros).
    ///
    /// Analogous to `Ipv4Addr::UNSPECIFIED` / `Ipv6Addr::UNSPECIFIED`.
    /// Must not appear as a source or destination in a routed packet.
    pub const UNSPECIFIED: Self = Self { asn: 0, host: 0 };

    /// The loopback IPv8 address `0.0.0.0.0.0.0.1` (ASN 0, host 1).
    ///
    /// Analogous to `127.0.0.1` (IPv4) / `::1` (IPv6).  Traffic to this
    /// address stays on the local host and must not be forwarded.
    pub const LOOPBACK: Self = Self { asn: 0, host: 1 };

    /// The limited broadcast address `255.255.255.255.255.255.255.255`.
    ///
    /// Per the draft, ASN = 0xFFFFFFFF and host = 0xFFFFFFFF.
    pub const BROADCAST: Self = Self { asn: u32::MAX, host: u32::MAX };

    /// Create a new address from an ASN and a host identifier.
    pub const fn new(asn: u32, host: u32) -> Self {
        Self { asn, host }
    }

    /// Returns `true` if this is the unspecified address (`0.0.0.0.0.0.0.0`).
    ///
    /// Packets carrying an unspecified source or destination are invalid and
    /// should be dropped.
    #[inline]
    pub const fn is_unspecified(self) -> bool {
        self.asn == 0 && self.host == 0
    }

    /// Returns `true` if this is the loopback address (`0.0.0.0.0.0.0.1`).
    ///
    /// Packets destined for the loopback address must not be forwarded to
    /// another node.
    #[inline]
    pub const fn is_loopback(self) -> bool {
        self.asn == 0 && self.host == 1
    }

    /// Returns `true` if this is the limited broadcast address
    /// (`255.255.255.255.255.255.255.255`).
    #[inline]
    pub const fn is_broadcast(self) -> bool {
        self.asn == u32::MAX && self.host == u32::MAX
    }

    /// Returns `true` if this is an IPv4-compatible address.
    ///
    /// Per the draft, an IPv8 address with ASN = `0.0.0.0` but non-zero host
    /// is processed under IPv4 compatibility rules.
    #[inline]
    pub const fn is_ipv4_compat(self) -> bool {
        self.asn == 0 && self.host != 0
    }

    /// Returns `true` if the ASN falls within the **internal zone** prefix
    /// `127.0.0.0/8` (first octet = 127).
    ///
    /// Internal zone addresses are used for intra-domain communication and
    /// must not be routed between ASNs.
    #[inline]
    pub const fn is_internal_zone(self) -> bool {
        (self.asn & 0xFF00_0000) == 0x7F00_0000
    }

    /// Returns `true` if the ASN falls within the **RINE peering** prefix
    /// `100.0.0.0/8` (first octet = 100).
    #[inline]
    pub const fn is_rine(self) -> bool {
        (self.asn & 0xFF00_0000) == 0x6400_0000
    }

    /// Returns `true` if the ASN falls within the **interior link** prefix
    /// `222.0.0.0/8` (first octet = 222).
    #[inline]
    pub const fn is_interior(self) -> bool {
        (self.asn & 0xFF00_0000) == 0xDE00_0000
    }

    /// Returns `true` if this is an **intra-ASN multicast** address.
    ///
    /// Intra-ASN multicast uses ASN = `0.0.0.0` and a host address in the
    /// range `224.0.0.0/4` (host first octet ≥ 0xE0).
    #[inline]
    pub const fn is_multicast_intra(self) -> bool {
        self.asn == 0 && (self.host & 0xF000_0000) == 0xE000_0000
    }

    /// Returns `true` if this is a **cross-ASN multicast** address.
    ///
    /// Cross-ASN multicast addresses have the upper 16 bits of the ASN set to
    /// `0xFFFF` (`ff.ff.x.x.*.*.*.*`).
    #[inline]
    pub const fn is_multicast_cross(self) -> bool {
        (self.asn & 0xFFFF_0000) == 0xFFFF_0000
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
    /// Two formats are accepted:
    ///
    /// * **8-octet** (canonical): `r1.r2.r3.r4.n1.n2.n3.n4`  
    ///   e.g. `0.0.251.240.10.0.1.1`  (7 dots)
    /// * **ASN dot-notation**: `<decimal_asn>.n1.n2.n3.n4`  
    ///   e.g. `64496.10.0.1.1`  (4 dots)
    ///
    /// Returns `None` if the string is malformed or any component is out of
    /// range.
    pub fn parse(s: &str) -> Option<Self> {
        let dots = s.bytes().filter(|&b| b == b'.').count();
        if dots == 7 {
            // Canonical 8-octet form: r1.r2.r3.r4.n1.n2.n3.n4
            let mut parts = s.splitn(9, '.');
            let r1: u8 = parts.next()?.parse().ok()?;
            let r2: u8 = parts.next()?.parse().ok()?;
            let r3: u8 = parts.next()?.parse().ok()?;
            let r4: u8 = parts.next()?.parse().ok()?;
            let n1: u8 = parts.next()?.parse().ok()?;
            let n2: u8 = parts.next()?.parse().ok()?;
            let n3: u8 = parts.next()?.parse().ok()?;
            let n4: u8 = parts.next()?.parse().ok()?;
            Some(Self {
                asn:  u32::from_be_bytes([r1, r2, r3, r4]),
                host: u32::from_be_bytes([n1, n2, n3, n4]),
            })
        } else if dots == 4 {
            // ASN dot-notation: <decimal_asn>.n1.n2.n3.n4
            let mut parts = s.splitn(5, '.');
            let asn: u32 = parts.next()?.parse().ok()?;
            let a: u8 = parts.next()?.parse().ok()?;
            let b: u8 = parts.next()?.parse().ok()?;
            let c: u8 = parts.next()?.parse().ok()?;
            let d: u8 = parts.next()?.parse().ok()?;
            Some(Self {
                asn,
                host: u32::from_be_bytes([a, b, c, d]),
            })
        } else {
            None
        }
    }
}

impl fmt::Display for Ipv8Addr {
    /// Format as the canonical 8-octet text representation `r.r.r.r.n.n.n.n`.
    ///
    /// Example: `0.0.251.240.10.0.1.1` (ASN 64496, host 10.0.1.1)
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [r1, r2, r3, r4] = self.asn.to_be_bytes();
        let [n1, n2, n3, n4] = self.host.to_be_bytes();
        write!(f, "{}.{}.{}.{}.{}.{}.{}.{}", r1, r2, r3, r4, n1, n2, n3, n4)
    }
}

impl core::str::FromStr for Ipv8Addr {
    type Err = ();

    /// Parse from the text representation `<asn>.<a>.<b>.<c>.<d>`.
    ///
    /// Returns `Err(())` for any malformed input.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_display() {
        // ASN 64512 = 0x0000_FC00 → octets [0, 0, 252, 0]
        let a = Ipv8Addr::new(64512, u32::from_be_bytes([192, 0, 2, 1]));
        assert_eq!(a.to_string(), "0.0.252.0.192.0.2.1");
    }

    #[test]
    fn addr_display_example_from_spec() {
        // Example from draft-thain-ipv8-00: ASN 64496 (0.0.251.240), host 10.0.1.1
        let a = Ipv8Addr::new(64496, u32::from_be_bytes([10, 0, 1, 1]));
        assert_eq!(a.to_string(), "0.0.251.240.10.0.1.1");
    }

    #[test]
    fn addr_parse_roundtrip() {
        // Use canonical 8-octet form for a lossless roundtrip.
        let original = "0.0.252.0.192.0.2.1";
        let addr = Ipv8Addr::parse(original).expect("parse failed");
        assert_eq!(addr.asn, 64512);
        assert_eq!(addr.host_octets(), [192, 0, 2, 1]);
        assert_eq!(addr.to_string(), original);
    }

    #[test]
    fn addr_parse_asn_dot_notation() {
        // The ASN dot-notation is accepted but not canonical.
        let addr = Ipv8Addr::parse("64512.192.0.2.1").expect("parse failed");
        assert_eq!(addr.asn, 64512);
        assert_eq!(addr.host_octets(), [192, 0, 2, 1]);
        // Canonical display uses 8-octet form.
        assert_eq!(addr.to_string(), "0.0.252.0.192.0.2.1");
    }

    #[test]
    fn addr_parse_invalid() {
        assert!(Ipv8Addr::parse("").is_none());
        assert!(Ipv8Addr::parse("64512.999.0.0.0").is_none()); // octet out of range
        assert!(Ipv8Addr::parse("abc.1.2.3.4").is_none());
        assert!(Ipv8Addr::parse("64512.1.2.3").is_none()); // too few parts
        assert!(Ipv8Addr::parse("1.2.3.4.5.6.7.256").is_none()); // 8-octet, last byte too large
    }

    #[test]
    fn addr_bytes_roundtrip() {
        let addr = Ipv8Addr::new(12345, 0x0a000001);
        let bytes = addr.to_bytes();
        let back = Ipv8Addr::from_bytes(bytes);
        assert_eq!(addr, back);
    }

    #[test]
    fn addr_unspecified_constant() {
        assert_eq!(Ipv8Addr::UNSPECIFIED.asn, 0);
        assert_eq!(Ipv8Addr::UNSPECIFIED.host, 0);
        assert!(Ipv8Addr::UNSPECIFIED.is_unspecified());
        assert!(!Ipv8Addr::UNSPECIFIED.is_loopback());
        assert_eq!(Ipv8Addr::UNSPECIFIED.to_string(), "0.0.0.0.0.0.0.0");
    }

    #[test]
    fn addr_loopback_constant() {
        assert_eq!(Ipv8Addr::LOOPBACK.asn, 0);
        assert_eq!(Ipv8Addr::LOOPBACK.host, 1);
        assert!(Ipv8Addr::LOOPBACK.is_loopback());
        assert!(!Ipv8Addr::LOOPBACK.is_unspecified());
        assert_eq!(Ipv8Addr::LOOPBACK.to_string(), "0.0.0.0.0.0.0.1");
    }

    #[test]
    fn addr_broadcast_constant() {
        assert!(Ipv8Addr::BROADCAST.is_broadcast());
        assert!(!Ipv8Addr::BROADCAST.is_unspecified());
        assert_eq!(Ipv8Addr::BROADCAST.to_string(),
                   "255.255.255.255.255.255.255.255");
    }

    #[test]
    fn addr_is_unspecified_false_for_nonzero() {
        assert!(!Ipv8Addr::new(1, 0).is_unspecified());
        assert!(!Ipv8Addr::new(0, 1).is_unspecified());
    }

    #[test]
    fn addr_is_ipv4_compat() {
        // ASN=0, host≠0 → IPv4-compatible
        assert!(Ipv8Addr::new(0, 0x0a000001).is_ipv4_compat());
        // ASN=0, host=0 → unspecified, not IPv4-compat
        assert!(!Ipv8Addr::UNSPECIFIED.is_ipv4_compat());
        // ASN≠0 → not IPv4-compat
        assert!(!Ipv8Addr::new(64512, 1).is_ipv4_compat());
    }

    #[test]
    fn addr_is_internal_zone() {
        // 127.0.0.0/8 ASN prefix
        let internal = Ipv8Addr::new(0x7F00_0001, 1); // ASN 127.0.0.1
        assert!(internal.is_internal_zone());
        assert!(!Ipv8Addr::new(64512, 1).is_internal_zone());
    }

    #[test]
    fn addr_is_rine() {
        // 100.0.0.0/8 ASN prefix
        let rine = Ipv8Addr::new(0x6400_0001, 1); // ASN 100.0.0.1
        assert!(rine.is_rine());
        assert!(!Ipv8Addr::new(64512, 1).is_rine());
    }

    #[test]
    fn addr_is_interior() {
        // 222.0.0.0/8 ASN prefix
        let interior = Ipv8Addr::new(0xDE00_0001, 1); // ASN 222.0.0.1
        assert!(interior.is_interior());
        assert!(!Ipv8Addr::new(64512, 1).is_interior());
    }

    #[test]
    fn addr_is_multicast_intra() {
        // ASN=0, host in 224.0.0.0/4
        let mc = Ipv8Addr::new(0, 0xE000_0001);
        assert!(mc.is_multicast_intra());
        assert!(!Ipv8Addr::new(0, 0x0a00_0001).is_multicast_intra());
        assert!(!Ipv8Addr::new(1, 0xE000_0001).is_multicast_intra());
    }

    #[test]
    fn addr_is_multicast_cross() {
        // ASN upper 16 bits = 0xFFFF
        let mc = Ipv8Addr::new(0xFFFF_0001, 1);
        assert!(mc.is_multicast_cross());
        assert!(!Ipv8Addr::new(64512, 1).is_multicast_cross());
    }

    #[test]
    fn addr_ord() {
        let a = Ipv8Addr::new(1, 0);
        let b = Ipv8Addr::new(2, 0);
        let c = Ipv8Addr::new(1, 1);
        assert!(a < b);
        assert!(a < c);
        assert!(c < b);
    }

    #[test]
    fn addr_from_str_ok() {
        // ASN dot-notation
        let addr: Ipv8Addr = "64512.10.0.0.1".parse().expect("parse failed");
        assert_eq!(addr.asn, 64512);
        assert_eq!(addr.host_octets(), [10, 0, 0, 1]);
    }

    #[test]
    fn addr_from_str_8octet_ok() {
        let addr: Ipv8Addr = "0.0.251.240.10.0.1.1".parse().expect("parse failed");
        assert_eq!(addr.asn, 64496);
        assert_eq!(addr.host_octets(), [10, 0, 1, 1]);
    }

    #[test]
    fn addr_from_str_invalid() {
        assert!("bad".parse::<Ipv8Addr>().is_err());
        assert!("64512.256.0.0.1".parse::<Ipv8Addr>().is_err());
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
