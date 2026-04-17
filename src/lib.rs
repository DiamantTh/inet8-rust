// SPDX-License-Identifier: GPL-3.0
//! IPv8 minimal network stack kernel module.
//!
//! This crate provides a complete, minimal IPv8 Layer-3 protocol
//! implementation intended to run as a Linux kernel module written in Rust.
//!
//! # Module layout
//! * [`addr`]    — address types and text-format parsing
//! * [`header`]  — on-wire packet header
//! * [`route`]   — static ASN-based routing table
//! * [`device`]  — per-interface address assignment
//! * [`socket`]  — socket family operations
//! * [`netlink`] — Netlink configuration interface

// When compiled outside a kernel build (e.g. `cargo test`) keep std available.
// When compiled as an actual kernel module the build system defines the
// `kernel` feature and we switch to no_std + alloc.
#![cfg_attr(feature = "kernel", no_std)]

#[cfg(feature = "kernel")]
extern crate alloc;

pub mod addr;
pub mod device;
pub mod header;
pub mod netlink;
pub mod route;
pub mod socket;

// ---------------------------------------------------------------------------
// Kernel module entry / exit (compiled only with --features kernel)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Protocol and address family constants
// ---------------------------------------------------------------------------

/// Address family number reserved for AF_INET8.
/// Chosen outside the currently assigned range; adjust to the real value
/// once it is allocated upstream.
pub const AF_INET8: u16 = 44;

/// IP-layer protocol number used to identify IPv8 payloads inside a carrier
/// network (analogous to IPv4 protocol field 41 for 6in4).
pub const IPPROTO_INET8: u8 = 253;

/// IPv8 version number (== 8).  Encoded in the upper nibble of `ver_ihl`.
pub const IPV8_VERSION: u8 = crate::header::VERSION;

/// Maximum transmission unit for IPv8 packets (bytes).
pub const IPV8_MTU: u16 = 1500;

/// Maximum payload size after the 28-byte IPv8 header.
pub const IPV8_MAX_PAYLOAD: u16 = IPV8_MTU - crate::header::HEADER_LEN as u16;

/// Upper-layer protocol number: ICMP (also used for ICMPv8).
pub const PROTO_ICMP: u8 = 1;
/// Upper-layer protocol number: TCP.
pub const PROTO_TCP: u8 = 6;
/// Upper-layer protocol number: UDP.
pub const PROTO_UDP: u8 = 17;
/// Upper-layer protocol number: OSPF8 (routing protocol for IPv8 networks).
pub const PROTO_OSPF8: u8 = 89;

/// Documentation / example ASN (65533).  Must not be used in production.
pub const ASN_DOC: u32 = 65533;
/// Private peering ASN (65534).  For internal use between directly connected
/// nodes.
pub const ASN_PRIVATE: u32 = 65534;

#[cfg(feature = "kernel")]
mod kernel_module {
    //! Kernel module registration stubs.
    //!
    //! In a real build these call the actual `kernel` crate APIs.
    //! They are kept as documented stubs here so the rest of the crate
    //! compiles cleanly without kernel headers.

    use super::*;
    use crate::route::RoutingTable;
    use crate::device::AddrTable;

    /// Global routing table (protected by a spin-lock in a real build).
    static mut ROUTE_TABLE: Option<RoutingTable> = None;
    /// Global address table (protected by a spin-lock in a real build).
    static mut ADDR_TABLE: Option<AddrTable> = None;

    /// Module initialisation — called by the kernel on `insmod`.
    ///
    /// # Safety
    /// Must be called exactly once from single-threaded module-init context.
    pub unsafe fn inet8_init() -> i32 {
        ROUTE_TABLE = Some(RoutingTable::new());
        ADDR_TABLE = Some(AddrTable::new());
        // Register socket family and Netlink handlers here.
        0 // 0 == success in kernel convention
    }

    /// Module cleanup — called by the kernel on `rmmod`.
    ///
    /// # Safety
    /// Must be called exactly once from single-threaded module-exit context,
    /// after `inet8_init` has succeeded.
    pub unsafe fn inet8_exit() {
        // Unregister socket family and Netlink handlers here.
        ROUTE_TABLE = None;
        ADDR_TABLE = None;
    }
}
