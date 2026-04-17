// SPDX-License-Identifier: GPL-3.0
//! Per-interface IPv8 address assignment.
//!
//! Addresses are assigned manually (§ 8 of the spec).  This module provides
//! add / remove / list operations over a table that maps interface indices to
//! IPv8 addresses.
//!
//! In a kernel build a spin-lock must protect access to the global table.

#[cfg(feature = "kernel")]
use alloc::vec::Vec;

use crate::addr::Ipv8Addr;

/// Maximum number of address assignments the table can hold.
pub const MAX_ADDRS: usize = 256;

/// An IPv8 address bound to a specific network interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAddr {
    /// Network interface index (`net_device->ifindex` in the kernel).
    pub ifindex: u32,
    /// The IPv8 address assigned to this interface.
    pub addr: Ipv8Addr,
}

impl DeviceAddr {
    /// Create a new device-address binding.
    pub const fn new(ifindex: u32, addr: Ipv8Addr) -> Self {
        Self { ifindex, addr }
    }
}

/// Errors returned by address-table operations.
#[derive(Debug, PartialEq, Eq)]
pub enum AddrError {
    /// The table has reached its maximum capacity.
    TableFull,
    /// The specified address was not found on the specified interface.
    NotFound,
    /// The address is already assigned to the interface.
    AlreadyExists,
    /// Interface index 0 is reserved and may not be used for address assignment.
    ///
    /// In Linux, valid `net_device` interface indices start at 1.
    InvalidIfindex,
}

/// Table of IPv8 addresses assigned to network interfaces.
///
/// Multiple addresses may be assigned to the same interface.  In a kernel
/// context access must be serialised externally (spin-lock at call site).
#[derive(Debug)]
pub struct AddrTable {
    entries: Vec<DeviceAddr>,
}

impl AddrTable {
    /// Create an empty address table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Assign `addr` to the interface identified by `ifindex`.
    ///
    /// Returns `Err(AddrError::InvalidIfindex)` when `ifindex` is 0 (reserved).
    /// Returns `Err(AddrError::AlreadyExists)` if the exact (ifindex, addr)
    /// pair is already present.
    pub fn add(&mut self, ifindex: u32, addr: Ipv8Addr) -> Result<(), AddrError> {
        if ifindex == 0 {
            return Err(AddrError::InvalidIfindex);
        }
        if self.entries.iter().any(|e| e.ifindex == ifindex && e.addr == addr) {
            return Err(AddrError::AlreadyExists);
        }
        if self.entries.len() >= MAX_ADDRS {
            return Err(AddrError::TableFull);
        }
        self.entries.push(DeviceAddr::new(ifindex, addr));
        Ok(())
    }

    /// Remove the assignment of `addr` from `ifindex`.
    ///
    /// Returns `Err(AddrError::NotFound)` when no matching entry exists.
    ///
    /// # Note
    /// Uses `swap_remove` internally (O(1)), so insertion order is **not**
    /// preserved after a removal.  Lookups are unaffected because they search
    /// by value, not by position.
    pub fn remove(&mut self, ifindex: u32, addr: Ipv8Addr) -> Result<(), AddrError> {
        let pos = self.entries
            .iter()
            .position(|e| e.ifindex == ifindex && e.addr == addr)
            .ok_or(AddrError::NotFound)?;
        self.entries.swap_remove(pos);
        Ok(())
    }

    /// List all addresses assigned to `ifindex`.
    pub fn list_by_ifindex(&self, ifindex: u32) -> impl Iterator<Item = &DeviceAddr> {
        self.entries.iter().filter(move |e| e.ifindex == ifindex)
    }

    /// Look up the interface index for an IPv8 address.
    ///
    /// Returns the first matching ifindex, or `None` if the address is not
    /// configured on any interface.
    pub fn lookup_ifindex(&self, addr: &Ipv8Addr) -> Option<u32> {
        self.entries.iter().find(|e| &e.addr == addr).map(|e| e.ifindex)
    }

    /// Return an iterator over all entries (read-only).
    pub fn iter(&self) -> impl Iterator<Item = &DeviceAddr> {
        self.entries.iter()
    }

    /// Number of address assignments currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AddrTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(asn: u32, host: u32) -> Ipv8Addr {
        Ipv8Addr::new(asn, host)
    }

    #[test]
    fn add_and_list() {
        let mut tbl = AddrTable::new();
        let a = addr(64512, 1);
        tbl.add(2, a).unwrap();
        let listed: Vec<_> = tbl.list_by_ifindex(2).collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].addr, a);
    }

    #[test]
    fn add_duplicate_rejected() {
        let mut tbl = AddrTable::new();
        let a = addr(1, 1);
        tbl.add(1, a).unwrap();
        assert_eq!(tbl.add(1, a), Err(AddrError::AlreadyExists));
    }

    #[test]
    fn remove_address() {
        let mut tbl = AddrTable::new();
        let a = addr(10, 10);
        tbl.add(3, a).unwrap();
        tbl.remove(3, a).unwrap();
        assert!(tbl.is_empty());
    }

    #[test]
    fn remove_nonexistent() {
        let mut tbl = AddrTable::new();
        assert_eq!(tbl.remove(1, addr(1, 1)), Err(AddrError::NotFound));
    }

    #[test]
    fn lookup_ifindex() {
        let mut tbl = AddrTable::new();
        let a = addr(64512, 0x0a000001);
        tbl.add(5, a).unwrap();
        assert_eq!(tbl.lookup_ifindex(&a), Some(5));
        assert_eq!(tbl.lookup_ifindex(&addr(99, 99)), None);
    }

    #[test]
    fn multiple_addrs_per_interface() {
        let mut tbl = AddrTable::new();
        tbl.add(2, addr(1, 1)).unwrap();
        tbl.add(2, addr(1, 2)).unwrap();
        let count = tbl.list_by_ifindex(2).count();
        assert_eq!(count, 2);
    }

    #[test]
    fn table_full() {
        let mut tbl = AddrTable::new();
        for i in 0..MAX_ADDRS as u32 {
            tbl.add(1, Ipv8Addr::new(i, 0)).unwrap();
        }
        let result = tbl.add(1, Ipv8Addr::new(MAX_ADDRS as u32, 0));
        assert_eq!(result, Err(AddrError::TableFull));
    }

    #[test]
    fn add_ifindex_zero_rejected() {
        let mut tbl = AddrTable::new();
        let result = tbl.add(0, Ipv8Addr::new(1, 1));
        assert_eq!(result, Err(AddrError::InvalidIfindex));
    }
}
