//! The inputs and the digests of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the XMSS code
//! of liboqs 0.16.0, such as `oqs_sig_stfl_xmss_sha256_h10_inner_thash_h`, with the same inputs,
//! for the one set of each `CoreHash` that the program linked. The program is not part of the
//! repository.

use crate::{CoreHash, HashAddress};
use OQSNativeSHA2::SHA256;
use alloc::string::String;
use alloc::vec::Vec;

/// Each core hash, with the XMSS object identifier of the set whose C functions gave the known
/// answers: XMSS-SHA2_10_256, XMSS-SHA2_10_192, XMSS-SHAKE_10_256, XMSS-SHA2_10_512,
/// XMSS-SHAKE_10_512, XMSS-SHAKE256_10_192 and XMSS-SHAKE256_10_256.
pub(crate) const coreHashes: [(CoreHash, u32); 7] = [
    (CoreHash::sha256N32, 0x01),
    (CoreHash::sha256N24, 0x0d),
    (CoreHash::shake128N32, 0x07),
    (CoreHash::sha512N64, 0x04),
    (CoreHash::shake256N64, 0x0a),
    (CoreHash::shake256N24, 0x13),
    (CoreHash::shake256N32, 0x10),
];

/// The bytes of an input with a label, the inputs of the C program: byte i is
/// `37 label + 11 i + i / 8` modulo 256.
pub(crate) fn pattern(length: usize, label: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (label * 37 + index * 11 + (index >> 3)) as u8)
        .collect()
}

/// The bytes in lower-case hexadecimal.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}

/// The SHA-256 of the bytes in lower-case hexadecimal, the digest of the C program.
pub(crate) fn digest(bytes: &[u8]) -> String {
    hex(&SHA256::hash(bytes))
}

/// The address of eight words, as the C program writes them in its `uint32_t addr[8]`.
pub(crate) fn address(words: [u32; 8]) -> HashAddress {
    let mut address = HashAddress::default();
    address.setLayer(words[0]);
    address.setTree((u64::from(words[1]) << 32) + u64::from(words[2]));
    address.setType(words[3]);
    address.setOTS(words[4]);
    address.setChain(words[5]);
    address.setHash(words[6]);
    address.setKeyAndMask(words[7]);
    address
}
