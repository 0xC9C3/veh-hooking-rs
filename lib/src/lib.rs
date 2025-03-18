#![doc = include_str!("../README.md")]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod guard;
pub mod hardware;

mod handler;
pub mod hook_base;
pub mod manager;
pub mod software;
mod util;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod base_tests;
