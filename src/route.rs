// SPDX-License-Identifier: GPL-3.0
//! Static ASN-based routing table.
//!
//! Routing decisions are made solely on the destination ASN; the host portion
//! of the address does not influence route selection (§ 7 of the spec).
//!
//! In a kernel build the `dev` field would be a `*mut net_device`.  Here it
//! is represented as an interface index (`u32`, i.e. `net_device->ifindex`)
//! so that the logic can be tested without kernel headers.

#[cfg(feature = "kernel")]
use alloc::vec::Vec;

/// Maximum number of routes the table can hold.
///
/// Matches the limit specified in the draft-thain-ipv8-00 reference
/// implementation (`IPV8_MAX_ROUTES = 1024`).
pub const MAX_ROUTES: usize = 1024;

/// A single static route entry.
///
/// Routes are ASN-scoped: all traffic to a given ASN is forwarded via the
/// nominated network interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inet8Route {
    /// Destination ASN.
    pub asn: u32,
    /// Outgoing network interface index (`net_device->ifindex` in the kernel).
    /// Value `0` means "no device assigned" / route disabled.
    pub dev_ifindex: u32,
}

impl Inet8Route {
    /// Create a new route entry.
    pub const fn new(asn: u32, dev_ifindex: u32) -> Self {
        Self { asn, dev_ifindex }
    }
}

/// Errors returned by routing-table operations.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteError {
    /// The table has reached its maximum capacity.
    TableFull,
    /// A route for the specified ASN was not found.
    NotFound,
}

/// A simple static routing table backed by a `Vec<Inet8Route>`.
///
/// In a kernel context access to this structure must be serialised with a
/// spin-lock (not shown here; done at the call site).
#[derive(Debug)]
pub struct RoutingTable {
    routes: Vec<Inet8Route>,
}

impl RoutingTable {
    /// Create an empty routing table.
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
        }
    }

    /// Insert or update a route.
    ///
    /// If a route for the same ASN already exists it is updated in-place.
    /// Otherwise the new route is appended, up to [`MAX_ROUTES`].
    pub fn insert(&mut self, route: Inet8Route) -> Result<(), RouteError> {
        if let Some(existing) = self.routes.iter_mut().find(|r| r.asn == route.asn) {
            *existing = route;
            return Ok(());
        }
        if self.routes.len() >= MAX_ROUTES {
            return Err(RouteError::TableFull);
        }
        self.routes.push(route);
        Ok(())
    }

    /// Remove the route for `asn`.
    ///
    /// Returns `Err(RouteError::NotFound)` when no matching route exists.
    ///
    /// # Note
    /// Uses `swap_remove` internally (O(1)), so insertion order is **not**
    /// preserved after a removal.  Route lookups are unaffected because they
    /// search by ASN, not by position.
    pub fn remove(&mut self, asn: u32) -> Result<Inet8Route, RouteError> {
        let pos = self.routes.iter().position(|r| r.asn == asn)
            .ok_or(RouteError::NotFound)?;
        Ok(self.routes.swap_remove(pos))
    }

    /// Look up the outgoing interface index for `asn`.
    ///
    /// First performs an exact ASN match; if none is found it falls back to
    /// the **default route** (ASN 0), mirroring the 0.0.0.0/0 convention
    /// used by inet4/inet6.  Routes whose `dev_ifindex` is 0 are treated as
    /// disabled and are never returned.
    ///
    /// ASN 0 is reserved as the default-route placeholder and is never a
    /// valid destination; `lookup(0)` always returns `None`.  This prevents
    /// a packet destined for the unspecified address from accidentally
    /// matching the default route and looping indefinitely.
    ///
    /// Returns `None` when no matching (and enabled) route exists.
    pub fn lookup(&self, asn: u32) -> Option<u32> {
        // ASN 0 is the default-route sentinel, not a routable destination.
        if asn == 0 {
            return None;
        }
        // Exact-match first; skip disabled routes (dev_ifindex == 0).
        if let Some(r) = self.routes.iter().find(|r| r.asn == asn && r.dev_ifindex != 0) {
            return Some(r.dev_ifindex);
        }
        // Fall back to the default route (ASN 0).
        self.routes
            .iter()
            .find(|r| r.asn == 0 && r.dev_ifindex != 0)
            .map(|r| r.dev_ifindex)
    }

    /// Return an iterator over all installed routes (read-only).
    pub fn iter(&self) -> impl Iterator<Item = &Inet8Route> {
        self.routes.iter()
    }

    /// Number of routes currently installed.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns `true` when the table contains no routes.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl Default for RoutingTable {
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

    #[test]
    fn insert_and_lookup() {
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(64512, 2)).unwrap();
        assert_eq!(tbl.lookup(64512), Some(2));
        assert_eq!(tbl.lookup(64513), None);
    }

    #[test]
    fn update_existing_route() {
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(64512, 2)).unwrap();
        tbl.insert(Inet8Route::new(64512, 3)).unwrap(); // update
        assert_eq!(tbl.lookup(64512), Some(3));
        assert_eq!(tbl.len(), 1);
    }

    #[test]
    fn remove_route() {
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(100, 1)).unwrap();
        let removed = tbl.remove(100).unwrap();
        assert_eq!(removed.asn, 100);
        assert_eq!(tbl.lookup(100), None);
        assert!(tbl.is_empty());
    }

    #[test]
    fn remove_nonexistent() {
        let mut tbl = RoutingTable::new();
        assert_eq!(tbl.remove(99), Err(RouteError::NotFound));
    }

    #[test]
    fn host_portion_ignored() {
        // Routing is ASN-only; host does not matter.
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(64512, 5)).unwrap();
        // Any host in ASN 64512 resolves to ifindex 5.
        assert_eq!(tbl.lookup(64512), Some(5));
    }

    #[test]
    fn table_full() {
        let mut tbl = RoutingTable::new();
        for i in 0..MAX_ROUTES as u32 {
            tbl.insert(Inet8Route::new(i, 1)).unwrap();
        }
        let result = tbl.insert(Inet8Route::new(MAX_ROUTES as u32, 1));
        assert_eq!(result, Err(RouteError::TableFull));
    }

    #[test]
    fn iter_routes() {
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(1, 10)).unwrap();
        tbl.insert(Inet8Route::new(2, 20)).unwrap();
        let asns: Vec<u32> = tbl.iter().map(|r| r.asn).collect();
        assert!(asns.contains(&1));
        assert!(asns.contains(&2));
    }

    #[test]
    fn disabled_route_not_returned() {
        // A route with dev_ifindex == 0 is disabled and must never be returned.
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(64512, 0)).unwrap();
        assert_eq!(tbl.lookup(64512), None);
    }

    #[test]
    fn default_route_fallback() {
        // ASN 0 acts as the default route when no exact match exists.
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(0, 9)).unwrap(); // default route via ifindex 9
        assert_eq!(tbl.lookup(64512), Some(9)); // unknown ASN → default
        assert_eq!(tbl.lookup(99999), Some(9));
    }

    #[test]
    fn exact_route_preferred_over_default() {
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(0, 9)).unwrap();     // default → ifindex 9
        tbl.insert(Inet8Route::new(64512, 3)).unwrap(); // exact  → ifindex 3
        assert_eq!(tbl.lookup(64512), Some(3)); // exact wins
        assert_eq!(tbl.lookup(64513), Some(9)); // falls back to default
    }

    #[test]
    fn default_route_asn_zero_lookup_returns_none() {
        // Looking up ASN 0 directly must not match the default route.
        let mut tbl = RoutingTable::new();
        tbl.insert(Inet8Route::new(0, 9)).unwrap();
        assert_eq!(tbl.lookup(0), None);
    }
}
