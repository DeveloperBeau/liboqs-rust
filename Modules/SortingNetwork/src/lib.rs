//! The constant-time sorting network of 32-bit values of liboqs, from djbsort of SUPERCOP.
//!
//! `SortingNetwork::sort` is `crypto_sort_int32`, which the NTRU-HPS code of PQClean uses to
//! place the coefficients of a polynomial of a fixed type. `SortingNetwork::sortUnsigned` is
//! `crypto_sort_uint32`, which `sntrup761.c` uses to place the coefficients of a short
//! polynomial. Both C forms have the same network of comparisons, so one network serves the
//! two families.

#![cfg_attr(not(feature = "std"), no_std)]

#[path = "SortingNetwork.rs"]
mod sortingNetwork;

pub use sortingNetwork::SortingNetwork;
