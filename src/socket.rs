// SPDX-License-Identifier: GPL-3.0
//! IPv8 socket abstraction layer.
//!
//! This module provides the data structures and logic for the AF_INET8 socket
//! family.  The kernel-facing registration (proto_ops / net_proto_family) is
//! handled at the call site in the kernel module entry point; here we define
//! the per-socket state and the operations that implement the required
//! syscall surface.
//!
//! Required operations (§ 4):
//! * `inet8_create`
//! * `inet8_bind`
//! * `inet8_connect`
//! * `inet8_sendmsg`
//! * `inet8_recvmsg`
//! * `inet8_release`

#[cfg(feature = "kernel")]
use alloc::collections::VecDeque;
#[cfg(feature = "kernel")]
use alloc::vec::Vec;
#[cfg(not(feature = "kernel"))]
use std::collections::VecDeque;

use crate::addr::{Ipv8Addr, SockAddrIn8};
use crate::header::{Ipv8Header, DEFAULT_TTL};
use crate::route::RoutingTable;
use crate::AF_INET8;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of packets that the per-socket receive queue may hold.
///
/// Mirrors the concept of `SO_RCVBUF` / `sk_rcvbuf` in the Linux kernel.
/// Excess packets delivered to a full queue are silently dropped to prevent
/// unbounded memory growth (analogous to the kernel's socket backlog limit).
pub const MAX_RECV_QUEUE_LEN: usize = 256;

// ---------------------------------------------------------------------------
// Socket state
// ---------------------------------------------------------------------------

/// State of an IPv8 socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketState {
    /// Initial state after creation.
    Unbound,
    /// A local address has been assigned via `inet8_bind`.
    Bound,
    /// A remote address has been fixed via `inet8_connect`.
    Connected,
    /// The socket has been closed.
    Released,
}

/// Error codes for socket operations.
#[derive(Debug, PartialEq, Eq)]
pub enum SocketError {
    /// The address family in `SockAddrIn8` is not `AF_INET8`.
    InvalidFamily,
    /// The socket is already bound.
    AlreadyBound,
    /// The socket must be bound before this operation.
    NotBound,
    /// The socket is already connected.
    AlreadyConnected,
    /// The socket must be connected or a destination must be specified.
    NotConnected,
    /// No route was found for the destination ASN.
    NoRoute,
    /// The socket has been released and can no longer be used.
    Released,
    /// The provided buffer is too small or the message is malformed.
    InvalidArgument,
}

/// In-kernel receive buffer entry.
///
/// In a real kernel build this would be an `sk_buff` on the socket's receive
/// queue.  Here we represent the received payload together with the source
/// address for testing purposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecvEntry {
    pub src: Ipv8Addr,
    pub data: Vec<u8>,
}

/// Per-socket state for an AF_INET8 socket.
///
/// In a kernel build this sits inside `struct sock` private data.
/// A spin-lock (not modelled here) must protect the `recv_queue`.
#[derive(Debug)]
pub struct Inet8Socket {
    /// Current socket state.
    pub state: SocketState,
    /// Locally bound address (set by `inet8_bind`).
    pub local: Option<SockAddrIn8>,
    /// Remote address (set by `inet8_connect`).
    pub remote: Option<SockAddrIn8>,
    /// Simulated receive queue.  In a kernel build this is the `sk_buff` queue.
    /// Uses `VecDeque` to allow O(1) FIFO dequeue from the front.
    pub recv_queue: VecDeque<RecvEntry>,
    /// Per-socket TTL for outgoing packets.
    ///
    /// Analogous to the `IP_TTL` / `IPV6_UNICAST_HOPS` socket options in
    /// inet4/inet6.  Defaults to [`DEFAULT_TTL`] and may be changed by the
    /// application between sends.
    pub ttl: u8,
}

impl Inet8Socket {
    // -----------------------------------------------------------------------
    // inet8_create
    // -----------------------------------------------------------------------

    /// Allocate and initialise a new IPv8 socket.
    ///
    /// Corresponds to the `inet8_create` proto_op called when userspace
    /// invokes `socket(AF_INET8, …)`.
    pub fn create() -> Self {
        Self {
            state: SocketState::Unbound,
            local: None,
            remote: None,
            recv_queue: VecDeque::new(),
            ttl: DEFAULT_TTL,
        }
    }

    // -----------------------------------------------------------------------
    // inet8_bind
    // -----------------------------------------------------------------------

    /// Bind the socket to a local IPv8 address.
    ///
    /// Corresponds to the `inet8_bind` proto_op called by `bind(2)`.
    ///
    /// # Errors
    /// * `InvalidFamily` — `addr.family != AF_INET8`
    /// * `AlreadyBound`  — the socket is already bound
    /// * `Released`      — the socket has been closed
    pub fn bind(&mut self, addr: SockAddrIn8) -> Result<(), SocketError> {
        self.check_not_released()?;
        if addr.family != AF_INET8 {
            return Err(SocketError::InvalidFamily);
        }
        if self.local.is_some() {
            return Err(SocketError::AlreadyBound);
        }
        self.local = Some(addr);
        self.state = SocketState::Bound;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // inet8_connect
    // -----------------------------------------------------------------------

    /// Connect the socket to a remote IPv8 address.
    ///
    /// Corresponds to the `inet8_connect` proto_op called by `connect(2)`.
    ///
    /// # Errors
    /// * `InvalidFamily`    — `addr.family != AF_INET8`
    /// * `AlreadyConnected` — already connected
    /// * `Released`         — the socket has been closed
    pub fn connect(&mut self, addr: SockAddrIn8) -> Result<(), SocketError> {
        self.check_not_released()?;
        if addr.family != AF_INET8 {
            return Err(SocketError::InvalidFamily);
        }
        if self.remote.is_some() {
            return Err(SocketError::AlreadyConnected);
        }
        self.remote = Some(addr);
        self.state = SocketState::Connected;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // inet8_sendmsg
    // -----------------------------------------------------------------------

    /// Send a message via this socket.
    ///
    /// Builds an [`Ipv8Header`], performs a route lookup, and returns the
    /// serialised packet (header + payload) together with the egress interface
    /// index.
    ///
    /// In a kernel build the caller passes the `sk_buff` to `dev_queue_xmit`
    /// using the returned `ifindex`.
    ///
    /// `dest` overrides the connected remote address and may be `None` for a
    /// connected socket.
    ///
    /// # Errors
    /// * `NotBound`      — no local address has been bound
    /// * `NotConnected`  — no remote address and `dest` is `None`
    /// * `NoRoute`       — routing table has no entry for the destination ASN
    /// * `InvalidArgument` — payload too large (> 65535 bytes)
    /// * `Released`      — the socket has been closed
    pub fn sendmsg(
        &self,
        dest: Option<&SockAddrIn8>,
        payload: &[u8],
        protocol: u8,
        routes: &RoutingTable,
    ) -> Result<(Vec<u8>, u32), SocketError> {
        self.check_not_released()?;

        let local = self.local.as_ref().ok_or(SocketError::NotBound)?;
        let remote = dest.or(self.remote.as_ref()).ok_or(SocketError::NotConnected)?;

        if payload.len() > u16::MAX as usize {
            return Err(SocketError::InvalidArgument);
        }

        let ifindex = routes.lookup(remote.asn).ok_or(SocketError::NoRoute)?;

        let hdr = Ipv8Header::new(
            protocol,
            self.ttl,
            payload.len() as u16,
            local.asn,
            local.addr,
            remote.asn,
            remote.addr,
        );

        let mut packet = Vec::with_capacity(crate::header::HEADER_LEN + payload.len());
        packet.extend_from_slice(&hdr.to_bytes());
        packet.extend_from_slice(payload);

        Ok((packet, ifindex))
    }

    // -----------------------------------------------------------------------
    // inet8_recvmsg (inbound path stub)
    // -----------------------------------------------------------------------

    /// Deliver an inbound packet to this socket's receive queue.
    ///
    /// This is called from the inbound packet handler after the header has
    /// been parsed and validated, and the correct socket has been identified
    /// by destination address.
    ///
    /// Packets delivered to a released socket are silently dropped.
    /// Packets that would exceed [`MAX_RECV_QUEUE_LEN`] are also silently
    /// dropped (receive-buffer overflow), mirroring the kernel's
    /// `SO_RCVBUF`-limited drop behaviour.
    ///
    /// In a kernel build this enqueues an `sk_buff`; here we store the
    /// source address + payload in a `VecDeque`.
    pub fn deliver(&mut self, src: Ipv8Addr, data: Vec<u8>) {
        if self.state == SocketState::Released {
            return; // drop: socket is released
        }
        if self.recv_queue.len() >= MAX_RECV_QUEUE_LEN {
            return; // drop: receive buffer full
        }
        self.recv_queue.push_back(RecvEntry { src, data });
    }

    /// Receive a message from the socket.
    ///
    /// Corresponds to the `inet8_recvmsg` proto_op.
    /// Returns the next queued [`RecvEntry`], or `None` if the queue is empty.
    ///
    /// In a kernel build this dequeues an `sk_buff` from the socket's receive
    /// queue and copies data into userspace.
    ///
    /// # Errors
    /// * `Released` — the socket has been closed
    pub fn recvmsg(&mut self) -> Result<Option<RecvEntry>, SocketError> {
        self.check_not_released()?;
        if self.recv_queue.is_empty() {
            return Ok(None);
        }
        Ok(self.recv_queue.pop_front())
    }

    // -----------------------------------------------------------------------
    // inet8_release
    // -----------------------------------------------------------------------

    /// Release (close) this socket.
    ///
    /// Corresponds to the `inet8_release` proto_op.  After this call the
    /// socket must not be used for any further operations.
    pub fn release(&mut self) {
        self.state = SocketState::Released;
        self.recv_queue.clear();
    }

    // -----------------------------------------------------------------------
    // Inbound packet processing
    // -----------------------------------------------------------------------

    /// Parse an inbound raw packet buffer.
    ///
    /// Returns the parsed header and a reference to the payload slice on
    /// success.  Used by the sk_buff receive hook before socket lookup.
    pub fn parse_packet(buf: &[u8]) -> Result<(Ipv8Header, &[u8]), SocketError> {
        let hdr = Ipv8Header::from_bytes(buf).ok_or(SocketError::InvalidArgument)?;
        let payload = hdr.payload(buf).ok_or(SocketError::InvalidArgument)?;
        Ok((hdr, payload))
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn check_not_released(&self) -> Result<(), SocketError> {
        if self.state == SocketState::Released {
            Err(SocketError::Released)
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::Inet8Route;

    fn make_local() -> SockAddrIn8 {
        SockAddrIn8::new(AF_INET8, 1234, 64512, 0x0a000001)
    }

    fn make_remote() -> SockAddrIn8 {
        SockAddrIn8::new(AF_INET8, 5678, 64513, 0x0a000002)
    }

    fn make_routes() -> RoutingTable {
        let mut rt = RoutingTable::new();
        rt.insert(Inet8Route::new(64513, 2)).unwrap();
        rt
    }

    // -- create --------------------------------------------------------------

    #[test]
    fn create_initial_state() {
        let s = Inet8Socket::create();
        assert_eq!(s.state, SocketState::Unbound);
        assert!(s.local.is_none());
        assert!(s.remote.is_none());
    }

    // -- bind ----------------------------------------------------------------

    #[test]
    fn bind_ok() {
        let mut s = Inet8Socket::create();
        s.bind(make_local()).unwrap();
        assert_eq!(s.state, SocketState::Bound);
    }

    #[test]
    fn bind_wrong_family() {
        let mut s = Inet8Socket::create();
        let bad = SockAddrIn8::new(2 /* AF_INET */, 0, 1, 1);
        assert_eq!(s.bind(bad), Err(SocketError::InvalidFamily));
    }

    #[test]
    fn bind_twice_rejected() {
        let mut s = Inet8Socket::create();
        s.bind(make_local()).unwrap();
        assert_eq!(s.bind(make_local()), Err(SocketError::AlreadyBound));
    }

    // -- connect -------------------------------------------------------------

    #[test]
    fn connect_ok() {
        let mut s = Inet8Socket::create();
        s.bind(make_local()).unwrap();
        s.connect(make_remote()).unwrap();
        assert_eq!(s.state, SocketState::Connected);
    }

    #[test]
    fn connect_wrong_family() {
        let mut s = Inet8Socket::create();
        let bad = SockAddrIn8::new(2, 0, 1, 1);
        assert_eq!(s.connect(bad), Err(SocketError::InvalidFamily));
    }

    #[test]
    fn connect_twice_rejected() {
        let mut s = Inet8Socket::create();
        s.connect(make_remote()).unwrap();
        assert_eq!(s.connect(make_remote()), Err(SocketError::AlreadyConnected));
    }

    // -- sendmsg -------------------------------------------------------------

    #[test]
    fn sendmsg_connected() {
        let mut s = Inet8Socket::create();
        s.bind(make_local()).unwrap();
        s.connect(make_remote()).unwrap();
        let rt = make_routes();
        let (pkt, ifindex) = s.sendmsg(None, b"hello", 17, &rt).unwrap();
        assert_eq!(ifindex, 2);
        // Verify we can parse the resulting packet back.
        let (hdr, payload) = Inet8Socket::parse_packet(&pkt).unwrap();
        assert_eq!(payload, b"hello");
        assert_eq!(hdr.dst_asn, 64513);
        assert_eq!(hdr.src_asn, 64512);
    }

    #[test]
    fn sendmsg_with_explicit_dest() {
        let mut s = Inet8Socket::create();
        s.bind(make_local()).unwrap();
        let rt = make_routes();
        let dest = make_remote();
        let (pkt, _) = s.sendmsg(Some(&dest), b"data", 6, &rt).unwrap();
        let (hdr, payload) = Inet8Socket::parse_packet(&pkt).unwrap();
        assert_eq!(payload, b"data");
        assert_eq!(hdr.protocol, 6);
    }

    #[test]
    fn sendmsg_no_local_fails() {
        let s = Inet8Socket::create();
        let rt = make_routes();
        assert_eq!(
            s.sendmsg(Some(&make_remote()), b"x", 17, &rt),
            Err(SocketError::NotBound)
        );
    }

    #[test]
    fn sendmsg_no_route_fails() {
        let mut s = Inet8Socket::create();
        s.bind(make_local()).unwrap();
        let empty_rt = RoutingTable::new();
        let result = s.sendmsg(Some(&make_remote()), b"x", 17, &empty_rt);
        assert_eq!(result, Err(SocketError::NoRoute));
    }

    // -- recvmsg / deliver ---------------------------------------------------

    #[test]
    fn deliver_and_recvmsg() {
        let mut s = Inet8Socket::create();
        let src = Ipv8Addr::new(64513, 1);
        s.deliver(src, b"world".to_vec());
        let entry = s.recvmsg().unwrap().unwrap();
        assert_eq!(entry.data, b"world");
        assert_eq!(entry.src, src);
        // Queue should now be empty.
        assert!(s.recvmsg().unwrap().is_none());
    }

    // -- release -------------------------------------------------------------

    #[test]
    fn released_socket_rejects_ops() {
        let mut s = Inet8Socket::create();
        s.release();
        assert_eq!(s.state, SocketState::Released);
        assert_eq!(s.bind(make_local()), Err(SocketError::Released));
        assert_eq!(s.connect(make_remote()), Err(SocketError::Released));
        assert_eq!(s.recvmsg(), Err(SocketError::Released));
    }

    // -- parse_packet --------------------------------------------------------

    #[test]
    fn parse_packet_roundtrip() {
        use crate::header::DEFAULT_TTL;
        let hdr = Ipv8Header::new(17, DEFAULT_TTL, 3, 1, 2, 3, 4);
        let mut buf = hdr.to_bytes().to_vec();
        buf.extend_from_slice(b"abc");
        let (ph, payload) = Inet8Socket::parse_packet(&buf).unwrap();
        assert_eq!(ph, hdr);
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn parse_packet_too_short() {
        assert!(Inet8Socket::parse_packet(&[0u8; 5]).is_err());
    }

    // -- ttl -----------------------------------------------------------------

    #[test]
    fn socket_default_ttl() {
        use crate::header::DEFAULT_TTL;
        let s = Inet8Socket::create();
        assert_eq!(s.ttl, DEFAULT_TTL);
    }

    #[test]
    fn sendmsg_ttl_in_packet() {
        let mut s = Inet8Socket::create();
        s.ttl = 30;
        s.bind(make_local()).unwrap();
        s.connect(make_remote()).unwrap();
        let rt = make_routes();
        let (pkt, _) = s.sendmsg(None, b"hi", 17, &rt).unwrap();
        let (hdr, _) = Inet8Socket::parse_packet(&pkt).unwrap();
        assert_eq!(hdr.ttl, 30);
    }

    // -- deliver guards ------------------------------------------------------

    #[test]
    fn deliver_to_released_socket_is_ignored() {
        let mut s = Inet8Socket::create();
        s.release();
        s.deliver(Ipv8Addr::new(1, 1), b"drop me".to_vec());
        // Queue must stay empty — the packet was dropped.
        assert!(s.recv_queue.is_empty());
    }

    #[test]
    fn deliver_respects_max_queue_len() {
        let mut s = Inet8Socket::create();
        let src = Ipv8Addr::new(1, 1);
        for _ in 0..MAX_RECV_QUEUE_LEN {
            s.deliver(src, b"x".to_vec());
        }
        // Queue is now at capacity; next deliver must be dropped.
        s.deliver(src, b"overflow".to_vec());
        assert_eq!(s.recv_queue.len(), MAX_RECV_QUEUE_LEN);
    }
}
