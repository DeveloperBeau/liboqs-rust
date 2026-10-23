/// The ways in which a signature of `xmss_core_fast.c` ends without a signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigningFailure {
    /// The index of the key is past its last one-time key. The C code wipes the key in memory and
    /// returns -2.
    exhausted,
    /// A forged state would make the C code read or write outside its buffers, copy between
    /// overlapping places or shift by the width of a value, so its behavior is undefined.
    undefined,
}
