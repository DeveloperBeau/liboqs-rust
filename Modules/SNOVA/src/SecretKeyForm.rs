/// The form of a secret key, the switch `sk_is_seed` of the C code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SecretKeyForm {
    /// The 48 bytes of the public seed and the secret seed, from which each signature expands
    /// the key again.
    seeds,
    /// The expanded key of `sk_pack`: the matrices A, B, Q1, Q2, T12, F11, F12 and F21 packed
    /// in halves, then the two seeds. The sets with `_esk` in their names keep this form.
    expanded,
}
