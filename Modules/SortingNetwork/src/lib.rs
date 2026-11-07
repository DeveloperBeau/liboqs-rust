//! The constant-time sorting network of 32-bit and 64-bit values of liboqs, from djbsort of
//! SUPERCOP.
//!
//! `SortingNetwork::sort` is `crypto_sort_int32`, which the NTRU-HPS code of PQClean uses to
//! place the coefficients of a polynomial of a fixed type, and `int32_sort`, which the Classic
//! McEliece code uses for the control bits of its Benes network. `SortingNetwork::sortUnsigned`
//! is `crypto_sort_uint32`, which `sntrup761.c` uses to place the coefficients of a short
//! polynomial. `SortingNetwork::sortWords` is `uint64_sort`, which the Classic McEliece code
//! uses to order the field elements of a key. Every C form has the same network of
//! comparisons, so one network serves the three families.

#![cfg_attr(not(feature = "std"), no_std)]

#[path = "SortingNetwork.rs"]
mod sortingNetwork;

pub use sortingNetwork::SortingNetwork;
