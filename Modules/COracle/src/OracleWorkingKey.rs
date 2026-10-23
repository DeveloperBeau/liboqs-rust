use OQSNativeEntities::SecretBytes;
use core::ffi::c_void;
use std::ffi::CString;

/// An LMS secret key of the C library with a working key of hash-sigs, which signs on from its
/// last state.
///
/// `OQS_SIG_STFL_sign` loads a new working key from the private key for each LMS signature, and
/// a load costs about one key generation. `COracle::loadLMSWorkingKey` loads the working key once,
/// and `COracle::signWithWorkingKey` signs with it and advances the serialized key in step, so
/// each signature and each advanced key is the one that `OQS_SIG_STFL_sign` gives. The working key
/// of liboqs does not sign on correctly past a subtree boundary, so the oracle verifies each
/// signature and loads the working key again when a signature fails. `OracleContract.rs` proves
/// both paths byte-identical. See `Documentation/Learnings/COracle.md`.
///
/// A key that a key generation gave is the only input. The working key is not a model of hostile
/// keys.
pub struct OracleWorkingKey {
    /// The liboqs name of the scheme.
    pub(crate) name: CString,
    /// The public key, which verifies each signature of the working key.
    pub(crate) publicKey: Vec<u8>,
    /// The serialized secret key, in step with the working key.
    pub(crate) secretKey: SecretBytes,
    /// The working key of hash-sigs in the memory of the C library, or null when the last load
    /// failed. Only `COracle` reads it, and the drop releases it.
    pub(crate) handle: *mut c_void,
}

impl OracleWorkingKey {
    /// The serialized secret key, advanced by each signature as `OQS_SIG_STFL_sign` stores it.
    pub fn secretKey(&self) -> &[u8] {
        self.secretKey.bytes()
    }
}
