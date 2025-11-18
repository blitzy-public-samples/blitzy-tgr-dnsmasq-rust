// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Common cross-platform network abstractions
//!
//! This module provides abstractions that work across all platforms.

use crate::error::Result;
use std::net::IpAddr;

/// Cross-platform network change event
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEvent {
    /// A new address was added to an interface
    AddressAdded {
        /// Interface name
        interface: String,
        /// IP address that was added
        address: IpAddr,
    },

    /// An address was removed from an interface
    AddressRemoved {
        /// Interface name
        interface: String,
        /// IP address that was removed
        address: IpAddr,
    },

    /// An interface went up
    InterfaceUp {
        /// Interface name
        interface: String,
    },

    /// An interface went down
    InterfaceDown {
        /// Interface name
        interface: String,
    },

    /// A route was added
    RouteAdded {
        /// Destination network
        destination: IpAddr,
        /// Gateway address
        gateway: Option<IpAddr>,
    },

    /// A route was removed
    RouteRemoved {
        /// Destination network
        destination: IpAddr,
    },
}

/// Trait for platform-specific network monitoring
pub trait NetworkMonitor {
    /// Start monitoring network changes
    ///
    /// # Errors
    ///
    /// Returns an error if monitoring cannot be started
    fn start_monitoring(&mut self) -> Result<()>;

    /// Get current interface addresses
    ///
    /// # Errors
    ///
    /// Returns an error if addresses cannot be retrieved
    fn get_interface_addresses(&self, interface: &str) -> Result<Vec<IpAddr>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_event_creation() {
        let event = NetworkEvent::AddressAdded {
            interface: "eth0".to_string(),
            address: "192.168.1.1".parse().unwrap(),
        };

        match event {
            NetworkEvent::AddressAdded { interface, address } => {
                assert_eq!(interface, "eth0");
                assert_eq!(address.to_string(), "192.168.1.1");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_network_event_equality() {
        let event1 = NetworkEvent::InterfaceUp { interface: "eth0".to_string() };
        let event2 = NetworkEvent::InterfaceUp { interface: "eth0".to_string() };
        let event3 = NetworkEvent::InterfaceDown { interface: "eth0".to_string() };

        assert_eq!(event1, event2);
        assert_ne!(event1, event3);
    }
}
