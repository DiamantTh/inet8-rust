// SPDX-License-Identifier: GPL-3.0
//! Netlink configuration interface for the IPv8 stack.
//!
//! This module defines the message types and serialisation format used to
//! configure the IPv8 stack via Netlink / rtnetlink (§ 9 of the spec).
//!
//! Message flow (conceptual):
//! ```text
//! userspace                  kernel
//!   ip addr add inet8 …  -->  Inet8NlMsg::AddAddr
//!   ip addr del inet8 …  -->  Inet8NlMsg::DelAddr
//!   ip route add inet8 … -->  Inet8NlMsg::AddRoute
//!   ip route del inet8 … -->  Inet8NlMsg::DelRoute
//!   ip addr show inet8   -->  Inet8NlMsg::GetAddr  (+ reply)
//!   ip route show inet8  -->  Inet8NlMsg::GetRoute (+ reply)
//! ```
//!
//! In a kernel build a proper Netlink family is registered via
//! `netlink_kernel_create` / `rtnl_register`; the message type constants and
//! payload structures defined here are shared between kernel and userspace.

#[cfg(feature = "kernel")]
use alloc::vec::Vec;

use crate::addr::Ipv8Addr;

// ---------------------------------------------------------------------------
// Message type discriminant
// ---------------------------------------------------------------------------

/// Netlink message type for AF_INET8 operations.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    /// Add an IPv8 address to an interface.
    AddAddr  = 1,
    /// Remove an IPv8 address from an interface.
    DelAddr  = 2,
    /// Query all addresses (returns zero or more [`AddrInfo`] responses).
    GetAddr  = 3,
    /// Install a static route.
    AddRoute = 4,
    /// Remove a static route.
    DelRoute = 5,
    /// Query all routes (returns zero or more [`RouteInfo`] responses).
    GetRoute = 6,
}

impl MsgType {
    /// Deserialise from a raw `u16`.  Returns `None` for unknown values.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::AddAddr),
            2 => Some(Self::DelAddr),
            3 => Some(Self::GetAddr),
            4 => Some(Self::AddRoute),
            5 => Some(Self::DelRoute),
            6 => Some(Self::GetRoute),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Address messages
// ---------------------------------------------------------------------------

/// Payload for `AddAddr` / `DelAddr` / `GetAddr` reply messages.
///
/// Wire layout (12 bytes, all fields big-endian):
/// ```text
/// ifindex(4) | asn(4) | host(4)
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    /// Target interface index.
    pub ifindex: u32,
    /// IPv8 ASN component of the address.
    pub asn: u32,
    /// IPv8 host component of the address.
    pub host: u32,
}

impl AddrInfo {
    /// Construct a new address-info message.
    pub const fn new(ifindex: u32, addr: Ipv8Addr) -> Self {
        Self { ifindex, asn: addr.asn, host: addr.host }
    }

    /// Return the embedded [`Ipv8Addr`].
    pub fn ipv8_addr(&self) -> Ipv8Addr {
        Ipv8Addr::new(self.asn, self.host)
    }

    /// Serialise to 12 big-endian bytes.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.ifindex.to_be_bytes());
        b[4..8].copy_from_slice(&self.asn.to_be_bytes());
        b[8..12].copy_from_slice(&self.host.to_be_bytes());
        b
    }

    /// Deserialise from 12 big-endian bytes.  Returns `None` when the slice
    /// is too short.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 12 {
            return None;
        }
        Some(Self {
            ifindex: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            asn:     u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            host:    u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
        })
    }
}

// ---------------------------------------------------------------------------
// Route messages
// ---------------------------------------------------------------------------

/// Payload for `AddRoute` / `DelRoute` / `GetRoute` reply messages.
///
/// Wire layout (8 bytes, all fields big-endian):
/// ```text
/// asn(4) | dev_ifindex(4)
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteInfo {
    /// Destination ASN.
    pub asn: u32,
    /// Egress interface index.
    pub dev_ifindex: u32,
}

impl RouteInfo {
    /// Construct a new route-info message.
    pub const fn new(asn: u32, dev_ifindex: u32) -> Self {
        Self { asn, dev_ifindex }
    }

    /// Serialise to 8 big-endian bytes.
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&self.asn.to_be_bytes());
        b[4..8].copy_from_slice(&self.dev_ifindex.to_be_bytes());
        b
    }

    /// Deserialise from 8 big-endian bytes.  Returns `None` when too short.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        Some(Self {
            asn:          u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            dev_ifindex:  u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        })
    }
}

// ---------------------------------------------------------------------------
// Top-level envelope
// ---------------------------------------------------------------------------

/// A complete IPv8 Netlink message.
///
/// In a real kernel build the [`MsgType`] discriminant lives in the standard
/// `nlmsghdr.nlmsg_type` field and the payload is carried in the `nlmsg`
/// data section.  This enum unifies both for in-kernel processing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inet8NlMsg {
    AddAddr(AddrInfo),
    DelAddr(AddrInfo),
    GetAddr,
    AddRoute(RouteInfo),
    DelRoute(RouteInfo),
    GetRoute,
}

impl Inet8NlMsg {
    /// Return the [`MsgType`] for this message.
    pub fn msg_type(&self) -> MsgType {
        match self {
            Self::AddAddr(_)  => MsgType::AddAddr,
            Self::DelAddr(_)  => MsgType::DelAddr,
            Self::GetAddr     => MsgType::GetAddr,
            Self::AddRoute(_) => MsgType::AddRoute,
            Self::DelRoute(_) => MsgType::DelRoute,
            Self::GetRoute    => MsgType::GetRoute,
        }
    }

    /// Serialise the message to bytes.
    ///
    /// Layout: `msg_type(2) | payload_len(2) | payload`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mt = self.msg_type() as u16;
        match self {
            Self::AddAddr(a) | Self::DelAddr(a) => {
                let payload = a.to_bytes();
                let mut out = Vec::with_capacity(4 + payload.len());
                out.extend_from_slice(&mt.to_be_bytes());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(&payload);
                out
            }
            Self::AddRoute(r) | Self::DelRoute(r) => {
                let payload = r.to_bytes();
                let mut out = Vec::with_capacity(4 + payload.len());
                out.extend_from_slice(&mt.to_be_bytes());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(&payload);
                out
            }
            Self::GetAddr | Self::GetRoute => {
                let mut out = Vec::with_capacity(4);
                out.extend_from_slice(&mt.to_be_bytes());
                out.extend_from_slice(&0u16.to_be_bytes()); // payload_len = 0
                out
            }
        }
    }

    /// Deserialise a message from bytes.
    ///
    /// Returns `None` on any malformed input.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 4 {
            return None;
        }
        let mt = MsgType::from_u16(u16::from_be_bytes([b[0], b[1]]))?;
        let payload_len = u16::from_be_bytes([b[2], b[3]]) as usize;
        let payload = b.get(4..4 + payload_len)?;

        match mt {
            MsgType::AddAddr  => Some(Self::AddAddr(AddrInfo::from_bytes(payload)?)),
            MsgType::DelAddr  => Some(Self::DelAddr(AddrInfo::from_bytes(payload)?)),
            MsgType::GetAddr  => Some(Self::GetAddr),
            MsgType::AddRoute => Some(Self::AddRoute(RouteInfo::from_bytes(payload)?)),
            MsgType::DelRoute => Some(Self::DelRoute(RouteInfo::from_bytes(payload)?)),
            MsgType::GetRoute => Some(Self::GetRoute),
        }
    }
}

// ---------------------------------------------------------------------------
// Netlink message processor
// ---------------------------------------------------------------------------

/// Process a single Netlink message against the provided tables.
///
/// Returns a `Vec` of response messages (may be empty for non-query
/// operations that succeed).  Returns `None` when the message is malformed.
///
/// In a kernel build this function is called from the Netlink receive handler
/// registered with `netlink_kernel_create`.
pub fn process_netlink_msg(
    msg: &Inet8NlMsg,
    addr_table: &mut crate::device::AddrTable,
    route_table: &mut crate::route::RoutingTable,
) -> Result<Vec<Inet8NlMsg>, &'static str> {
    match msg {
        Inet8NlMsg::AddAddr(info) => {
            addr_table
                .add(info.ifindex, info.ipv8_addr())
                .map_err(|e| match e {
                    crate::device::AddrError::InvalidIfindex => "invalid interface index",
                    crate::device::AddrError::AlreadyExists  => "address already assigned to interface",
                    crate::device::AddrError::TableFull      => "address table full",
                    crate::device::AddrError::NotFound       => "address not found",
                })?;
            Ok(Vec::new())
        }
        Inet8NlMsg::DelAddr(info) => {
            addr_table
                .remove(info.ifindex, info.ipv8_addr())
                .map_err(|e| match e {
                    crate::device::AddrError::NotFound       => "address not found on interface",
                    crate::device::AddrError::InvalidIfindex => "invalid interface index",
                    crate::device::AddrError::AlreadyExists  => "address already assigned to interface",
                    crate::device::AddrError::TableFull      => "address table full",
                })?;
            Ok(Vec::new())
        }
        Inet8NlMsg::GetAddr => {
            let replies = addr_table
                .iter()
                .map(|e| Inet8NlMsg::AddAddr(AddrInfo::new(e.ifindex, e.addr)))
                .collect();
            Ok(replies)
        }
        Inet8NlMsg::AddRoute(info) => {
            route_table
                .insert(crate::route::Inet8Route::new(info.asn, info.dev_ifindex))
                .map_err(|e| match e {
                    crate::route::RouteError::TableFull => "route table full",
                    crate::route::RouteError::NotFound  => "route not found",
                })?;
            Ok(Vec::new())
        }
        Inet8NlMsg::DelRoute(info) => {
            route_table
                .remove(info.asn)
                .map(|_| ())
                .map_err(|e| match e {
                    crate::route::RouteError::NotFound  => "route not found",
                    crate::route::RouteError::TableFull => "route table full",
                })?;
            Ok(Vec::new())
        }
        Inet8NlMsg::GetRoute => {
            let replies = route_table
                .iter()
                .map(|r| Inet8NlMsg::AddRoute(RouteInfo::new(r.asn, r.dev_ifindex)))
                .collect();
            Ok(replies)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::AddrTable;
    use crate::route::RoutingTable;

    // -- MsgType -------------------------------------------------------------

    #[test]
    fn msg_type_roundtrip() {
        for v in 1u16..=6 {
            let mt = MsgType::from_u16(v).unwrap();
            assert_eq!(mt as u16, v);
        }
        assert!(MsgType::from_u16(0).is_none());
        assert!(MsgType::from_u16(7).is_none());
    }

    // -- AddrInfo ------------------------------------------------------------

    #[test]
    fn addr_info_roundtrip() {
        let a = AddrInfo::new(3, Ipv8Addr::new(64512, 0x0a000001));
        let bytes = a.to_bytes();
        let back = AddrInfo::from_bytes(&bytes).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn addr_info_too_short() {
        assert!(AddrInfo::from_bytes(&[0u8; 11]).is_none());
    }

    // -- RouteInfo -----------------------------------------------------------

    #[test]
    fn route_info_roundtrip() {
        let r = RouteInfo::new(64512, 5);
        let bytes = r.to_bytes();
        let back = RouteInfo::from_bytes(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn route_info_too_short() {
        assert!(RouteInfo::from_bytes(&[0u8; 7]).is_none());
    }

    // -- Inet8NlMsg serialisation -------------------------------------------

    #[test]
    fn nl_msg_add_addr_roundtrip() {
        let ai = AddrInfo::new(2, Ipv8Addr::new(1, 2));
        let msg = Inet8NlMsg::AddAddr(ai);
        let bytes = msg.to_bytes();
        let back = Inet8NlMsg::from_bytes(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn nl_msg_add_route_roundtrip() {
        let ri = RouteInfo::new(64512, 3);
        let msg = Inet8NlMsg::AddRoute(ri);
        let bytes = msg.to_bytes();
        let back = Inet8NlMsg::from_bytes(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn nl_msg_get_addr_roundtrip() {
        let msg = Inet8NlMsg::GetAddr;
        let bytes = msg.to_bytes();
        let back = Inet8NlMsg::from_bytes(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn nl_msg_too_short() {
        assert!(Inet8NlMsg::from_bytes(&[0u8; 3]).is_none());
    }

    // -- process_netlink_msg ------------------------------------------------

    #[test]
    fn process_add_and_get_addr() {
        let mut at = AddrTable::new();
        let mut rt = RoutingTable::new();
        let ai = AddrInfo::new(1, Ipv8Addr::new(64512, 1));
        process_netlink_msg(&Inet8NlMsg::AddAddr(ai), &mut at, &mut rt).unwrap();
        let replies =
            process_netlink_msg(&Inet8NlMsg::GetAddr, &mut at, &mut rt).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0], Inet8NlMsg::AddAddr(ai));
    }

    #[test]
    fn process_add_and_del_addr() {
        let mut at = AddrTable::new();
        let mut rt = RoutingTable::new();
        let ai = AddrInfo::new(1, Ipv8Addr::new(1, 1));
        process_netlink_msg(&Inet8NlMsg::AddAddr(ai), &mut at, &mut rt).unwrap();
        process_netlink_msg(&Inet8NlMsg::DelAddr(ai), &mut at, &mut rt).unwrap();
        assert!(at.is_empty());
    }

    #[test]
    fn process_add_and_get_route() {
        let mut at = AddrTable::new();
        let mut rt = RoutingTable::new();
        let ri = RouteInfo::new(64512, 2);
        process_netlink_msg(&Inet8NlMsg::AddRoute(ri), &mut at, &mut rt).unwrap();
        let replies =
            process_netlink_msg(&Inet8NlMsg::GetRoute, &mut at, &mut rt).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0], Inet8NlMsg::AddRoute(ri));
    }

    #[test]
    fn process_del_nonexistent_addr_fails() {
        let mut at = AddrTable::new();
        let mut rt = RoutingTable::new();
        let ai = AddrInfo::new(1, Ipv8Addr::new(1, 1));
        assert!(process_netlink_msg(&Inet8NlMsg::DelAddr(ai), &mut at, &mut rt).is_err());
    }

    #[test]
    fn process_del_nonexistent_route_fails() {
        let mut at = AddrTable::new();
        let mut rt = RoutingTable::new();
        let ri = RouteInfo::new(99, 1);
        assert!(process_netlink_msg(&Inet8NlMsg::DelRoute(ri), &mut at, &mut rt).is_err());
    }

    #[test]
    fn process_add_addr_invalid_ifindex_fails() {
        let mut at = AddrTable::new();
        let mut rt = RoutingTable::new();
        // ifindex == 0 is reserved and must be rejected.
        let ai = AddrInfo::new(0, Ipv8Addr::new(1, 1));
        let err = process_netlink_msg(&Inet8NlMsg::AddAddr(ai), &mut at, &mut rt)
            .unwrap_err();
        assert_eq!(err, "invalid interface index");
    }

    #[test]
    fn process_add_addr_duplicate_fails() {
        let mut at = AddrTable::new();
        let mut rt = RoutingTable::new();
        let ai = AddrInfo::new(1, Ipv8Addr::new(1, 1));
        process_netlink_msg(&Inet8NlMsg::AddAddr(ai), &mut at, &mut rt).unwrap();
        let err = process_netlink_msg(&Inet8NlMsg::AddAddr(ai), &mut at, &mut rt)
            .unwrap_err();
        assert_eq!(err, "address already assigned to interface");
    }

    #[test]
    fn process_del_route_not_found_error_message() {
        let mut at = AddrTable::new();
        let mut rt = RoutingTable::new();
        let ri = RouteInfo::new(123, 1);
        let err = process_netlink_msg(&Inet8NlMsg::DelRoute(ri), &mut at, &mut rt)
            .unwrap_err();
        assert_eq!(err, "route not found");
    }
}
