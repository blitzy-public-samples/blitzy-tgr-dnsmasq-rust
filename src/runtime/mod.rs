// Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! Async runtime and event loop infrastructure
//!
//! This module provides the async runtime components that replace C's poll()-based
//! event loop with Rust's tokio async/await model.

// Temporarily commented out until EventLoop implementation is fully compatible with current service APIs
// pub mod event_loop;
pub mod reactor;
pub mod tasks;
