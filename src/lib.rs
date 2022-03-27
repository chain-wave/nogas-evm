//! Ethereum Virtual Machine implementation in Rust

#![no_std]

extern crate alloc;

pub use evm_core::*;
pub use evm_runtime::*;

pub mod backend;
pub mod executor;
