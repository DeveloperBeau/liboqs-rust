/// The form of the keys of a parameter set: `_OV_CLASSIC`, `_OV_PKC` or `_OV_PKC_SKC` of
/// `params.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyForm {
    /// The classic form: the public key holds the whole public map, and the secret key holds
    /// its seed, the oil matrix and the blocks that a signature uses.
    classic,
    /// The `pkc` form: the public key is the public seed and the oil block, and a verification
    /// expands the other blocks from the seed. The secret key is the classic secret key.
    compressedPublicKey,
    /// The `pkc-skc` form: the public key of `compressedPublicKey`, and the secret key is its
    /// 32-byte seed, which a signature expands.
    compressedKeys,
}
