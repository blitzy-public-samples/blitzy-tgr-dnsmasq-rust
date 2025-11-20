// Copyright (C) 2025 Dnsmasq Contributors
// SPDX-License-Identifier: GPL-2.0-or-later OR GPL-3.0-or-later

//! Build script for dnsmasq
//!
//! This build script handles platform-specific library linking requirements,
//! particularly for optional features that depend on C libraries.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Handle ubus feature - OpenWrt-specific C library
    #[cfg(feature = "ubus")]
    {
        // Check if libubus is available via pkg-config
        let has_libubus = Command::new("pkg-config")
            .args(["--exists", "libubus"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);

        if has_libubus {
            // Link against libubus
            println!("cargo:rustc-link-lib=ubus");
            println!("cargo:rustc-link-lib=ubox");

            // Get library path from pkg-config
            if let Ok(output) =
                Command::new("pkg-config").args(["--libs-only-L", "libubus"]).output()
            {
                if output.status.success() {
                    let paths = String::from_utf8_lossy(&output.stdout);
                    for path in paths.split_whitespace() {
                        if let Some(stripped) = path.strip_prefix("-L") {
                            println!("cargo:rustc-link-search=native={}", stripped);
                        }
                    }
                }
            }
            
            // Enable cfg flag to indicate libubus is available
            println!("cargo:rustc-cfg=has_libubus");
        } else {
            // libubus not available - emit warning and use stub implementation
            // This allows compilation and linking on non-OpenWrt systems
            println!("cargo:warning=libubus not found via pkg-config. The 'ubus' feature requires libubus development package.");
            println!("cargo:warning=On OpenWrt, install libubus-dev. On other systems, the ubus module will use a stub implementation.");
            println!("cargo:warning=To build without warnings, use: cargo build --features=<desired-features> (excluding ubus)");

            // DO NOT emit link instructions - we'll use a stub implementation instead
            // The ubus module will compile but any runtime use will fail
            // This is acceptable for development/testing on non-OpenWrt systems
        }
    }
}
