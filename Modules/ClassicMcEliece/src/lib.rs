//! Classic McEliece, the code-based key encapsulation mechanism of round 4 of the NIST process,
//! as liboqs ships it.
//!
//! `ClassicMcEliece` gives the bytes of the ten liboqs algorithms from
//! `Classic-McEliece-348864` to `Classic-McEliece-8192128f`, whose C code is the portable code
//! of the Classic McEliece team in PQClean. The code is a binary Goppa code over the field of
//! `GaloisField`, with the Goppa polynomial of `GoppaPolynomial`. The key generation orders the
//! field elements with the sorting network of the shared crate `oqs-native-sorting-network`,
//! brings the parity-check matrix of `ParityCheckMatrix` into systematic or semi-systematic
//! form, and stores the support as the control bits of a Benes network, `ControlBits` and
//! `BenesNetwork`. `Encryption` makes the error vector and its syndrome, and `Decryption`
//! decodes it with the Berlekamp-Massey algorithm.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[path = "BenesNetwork.rs"]
mod benesNetwork;
#[path = "ClassicMcEliece.rs"]
mod classicMcEliece;
#[path = "ControlBits.rs"]
mod controlBits;
#[path = "Decryption.rs"]
mod decryption;
#[path = "Encryption.rs"]
mod encryption;
#[path = "GaloisField.rs"]
mod galoisField;
#[path = "GoppaPolynomial.rs"]
mod goppaPolynomial;
#[path = "Parameters.rs"]
mod parameters;
#[path = "ParityCheckMatrix.rs"]
mod parityCheckMatrix;

pub use classicMcEliece::ClassicMcEliece;
use parameters::Parameters;

#[cfg(test)]
#[path = "TestSupport.rs"]
mod testSupport;
