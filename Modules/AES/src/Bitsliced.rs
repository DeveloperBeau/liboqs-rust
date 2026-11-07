//! The bitsliced AES rounds of liboqs `aes_c.c` (from BearSSL `aes_ct64`).
//!
//! Translated from liboqs `src/common/aes/aes_c.c`, which is based on BearSSL.
//! Copyright (c) 2016 Thomas Pornin. MIT license, see `THIRD_PARTY_NOTICES.md`.
//!
//! Eight 64-bit words hold four blocks: word `q[i]` holds bit `i` of each of the 64 state
//! bytes. The S-box is the circuit of Boyar and Peralta, so it has no table lookup.
//!
//! Where the C code joins bit fields that cannot overlap with `|`, this code uses `+`. The
//! value is the same, but a mutation of `+` changes it, where a mutation of `|` to `^` would
//! not. See `Documentation/Learnings/MutationTesting.md`.

/// Reads little-endian 32-bit words, as `br_range_dec32le` does.
pub fn decodeLittleEndian(bytes: &[u8], words: &mut [u32]) {
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
}

/// Applies the AES S-box to the eight bitsliced words, as `br_aes_ct64_bitslice_Sbox` does.
///
/// The variables `x0` to `x7` are the input bits from high to low, as in the paper.
fn substitute(q: &mut [u64; 8]) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // The top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // The non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // The bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/// Swaps bit groups between two words, as the `SWAPN` macro of `br_aes_ct64_ortho` does.
fn swapBits(
    q: &mut [u64; 8],
    first: usize,
    second: usize,
    lowMask: u64,
    highMask: u64,
    shift: u32,
) {
    let a = q[first];
    let b = q[second];
    q[first] = (a & lowMask) + ((b & lowMask) << shift);
    q[second] = ((a & highMask) >> shift) + (b & highMask);
}

/// Transposes the bits of the eight words, between the bitsliced form and the byte form, as
/// `br_aes_ct64_ortho` does. The transposition is its own inverse.
fn orthogonalize(q: &mut [u64; 8]) {
    for (first, second) in [(0, 1), (2, 3), (4, 5), (6, 7)] {
        swapBits(q, first, second, 0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 1);
    }
    for (first, second) in [(0, 2), (1, 3), (4, 6), (5, 7)] {
        swapBits(q, first, second, 0x3333333333333333, 0xCCCCCCCCCCCCCCCC, 2);
    }
    for (first, second) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
        swapBits(q, first, second, 0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0, 4);
    }
}

/// Spreads four 32-bit words of one block over two 64-bit words, as
/// `br_aes_ct64_interleave_in` does.
fn interleaveIn(words: &[u32]) -> (u64, u64) {
    let mut x = [
        u64::from(words[0]),
        u64::from(words[1]),
        u64::from(words[2]),
        u64::from(words[3]),
    ];
    for value in x.iter_mut() {
        *value |= *value << 16;
        *value &= 0x0000FFFF0000FFFF;
        *value |= *value << 8;
        *value &= 0x00FF00FF00FF00FF;
    }
    (x[0] + (x[2] << 8), x[1] + (x[3] << 8))
}

/// Gathers the four 32-bit words of one block from two 64-bit words, as
/// `br_aes_ct64_interleave_out` does.
fn interleaveOut(first: u64, second: u64) -> [u32; 4] {
    let mut x = [
        first & 0x00FF00FF00FF00FF,
        second & 0x00FF00FF00FF00FF,
        (first >> 8) & 0x00FF00FF00FF00FF,
        (second >> 8) & 0x00FF00FF00FF00FF,
    ];
    for value in x.iter_mut() {
        *value |= *value >> 8;
        *value &= 0x0000FFFF0000FFFF;
    }
    x.map(|value| (value as u32) + ((value >> 16) as u32))
}

/// Applies the S-box to each byte of a word, as `sub_word` does.
fn substituteWord(word: u32) -> u32 {
    let mut q = [0u64; 8];
    q[0] = u64::from(word);
    orthogonalize(&mut q);
    substitute(&mut q);
    orthogonalize(&mut q);
    q[0] as u32
}

/// The round constants of the key schedule: the powers of x in GF(2^8). AES-128 uses the first
/// ten, AES-256 the first seven, and Rijndael with a 256-bit block and key all fourteen.
const roundConstants: [u32; 14] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D,
];

/// Computes the compressed bitsliced round keys of a key of 16 or 32 bytes, as
/// `br_aes_ct64_keysched` does.
pub fn scheduleKey(compressedKeys: &mut [u64; 30], key: &[u8]) {
    let rounds = 10 + (key.len() - 16) / 4;
    let keyWords = key.len() / 4;
    let totalWords = (rounds + 1) * 4;
    let mut schedule = [0u32; 60];
    decodeLittleEndian(key, &mut schedule[..keyWords]);
    let mut temporary = schedule[keyWords - 1];
    let mut wordInKey = 0;
    let mut roundIndex = 0;
    for index in keyWords..totalWords {
        if wordInKey == 0 {
            temporary = temporary.rotate_right(8);
            temporary = substituteWord(temporary) ^ roundConstants[roundIndex];
        } else if keyWords == 8 && wordInKey == 4 {
            // Only AES-256 substitutes the fourth word of each group of eight.
            temporary = substituteWord(temporary);
        }
        temporary ^= schedule[index - keyWords];
        schedule[index] = temporary;
        wordInKey += 1;
        if wordInKey == keyWords {
            wordInKey = 0;
            roundIndex += 1;
        }
    }
    for (index, pair) in (0..totalWords)
        .step_by(4)
        .zip(compressedKeys.chunks_exact_mut(2))
    {
        let mut q = [0u64; 8];
        let (low, high) = interleaveIn(&schedule[index..index + 4]);
        q[0] = low;
        q[4] = high;
        q[1] = q[0];
        q[2] = q[0];
        q[3] = q[0];
        q[5] = q[4];
        q[6] = q[4];
        q[7] = q[4];
        orthogonalize(&mut q);
        pair[0] = (q[0] & 0x1111111111111111)
            + (q[1] & 0x2222222222222222)
            + (q[2] & 0x4444444444444444)
            + (q[3] & 0x8888888888888888);
        pair[1] = (q[4] & 0x1111111111111111)
            + (q[5] & 0x2222222222222222)
            + (q[6] & 0x4444444444444444)
            + (q[7] & 0x8888888888888888);
    }
}

/// Expands the compressed round keys to eight words for each round, as
/// `br_aes_ct64_skey_expand` does.
pub fn expandScheduledKey(
    expandedKeys: &mut [u64; 120],
    compressedKeys: &[u64; 30],
    rounds: usize,
) {
    let count = (rounds + 1) * 2;
    for (compressed, expanded) in compressedKeys[..count]
        .iter()
        .zip(expandedKeys.chunks_exact_mut(4))
    {
        let x0 = compressed & 0x1111111111111111;
        let x1 = (compressed & 0x2222222222222222) >> 1;
        let x2 = (compressed & 0x4444444444444444) >> 2;
        let x3 = (compressed & 0x8888888888888888) >> 3;
        // Each mask bit becomes four equal bits: (x << 4) - x repeats a bit across a nibble.
        expanded[0] = (x0 << 4).wrapping_sub(x0);
        expanded[1] = (x1 << 4).wrapping_sub(x1);
        expanded[2] = (x2 << 4).wrapping_sub(x2);
        expanded[3] = (x3 << 4).wrapping_sub(x3);
    }
}

fn addRoundKey(q: &mut [u64; 8], roundKey: &[u64]) {
    for (word, key) in q.iter_mut().zip(roundKey) {
        *word ^= key;
    }
}

fn shiftRows(q: &mut [u64; 8]) {
    for word in q.iter_mut() {
        let x = *word;
        *word = (x & 0x000000000000FFFF)
            + ((x & 0x00000000FFF00000) >> 4)
            + ((x & 0x00000000000F0000) << 12)
            + ((x & 0x0000FF0000000000) >> 8)
            + ((x & 0x000000FF00000000) << 8)
            + ((x & 0xF000000000000000) >> 12)
            + ((x & 0x0FFF000000000000) << 4);
    }
}

fn mixColumns(q: &mut [u64; 8]) {
    let original = *q;
    let rotated = original.map(|word| word.rotate_right(16));
    let swapHalves = |word: u64| word.rotate_left(32);
    q[0] = original[7] ^ rotated[7] ^ rotated[0] ^ swapHalves(original[0] ^ rotated[0]);
    q[1] = original[0]
        ^ rotated[0]
        ^ original[7]
        ^ rotated[7]
        ^ rotated[1]
        ^ swapHalves(original[1] ^ rotated[1]);
    q[2] = original[1] ^ rotated[1] ^ rotated[2] ^ swapHalves(original[2] ^ rotated[2]);
    q[3] = original[2]
        ^ rotated[2]
        ^ original[7]
        ^ rotated[7]
        ^ rotated[3]
        ^ swapHalves(original[3] ^ rotated[3]);
    q[4] = original[3]
        ^ rotated[3]
        ^ original[7]
        ^ rotated[7]
        ^ rotated[4]
        ^ swapHalves(original[4] ^ rotated[4]);
    q[5] = original[4] ^ rotated[4] ^ rotated[5] ^ swapHalves(original[5] ^ rotated[5]);
    q[6] = original[5] ^ rotated[5] ^ rotated[6] ^ swapHalves(original[6] ^ rotated[6]);
    q[7] = original[6] ^ rotated[6] ^ rotated[7] ^ swapHalves(original[7] ^ rotated[7]);
}

/// Encrypts four blocks given as 16 little-endian words, as `aes_ecb4x` does.
pub fn encryptFourBlocks(
    blockWords: &[u32; 16],
    expandedKeys: &[u64; 120],
    rounds: usize,
) -> [u8; 64] {
    let mut q = [0u64; 8];
    for block in 0..4 {
        let (low, high) = interleaveIn(&blockWords[block * 4..block * 4 + 4]);
        q[block] = low;
        q[block + 4] = high;
    }
    orthogonalize(&mut q);
    addRoundKey(&mut q, &expandedKeys[..8]);
    for round in 1..rounds {
        substitute(&mut q);
        shiftRows(&mut q);
        mixColumns(&mut q);
        addRoundKey(&mut q, &expandedKeys[round * 8..round * 8 + 8]);
    }
    substitute(&mut q);
    shiftRows(&mut q);
    addRoundKey(&mut q, &expandedKeys[rounds * 8..rounds * 8 + 8]);
    orthogonalize(&mut q);
    let mut output = [0u8; 64];
    for block in 0..4 {
        let words = interleaveOut(q[block], q[block + 4]);
        for (chunk, word) in output[block * 16..block * 16 + 16]
            .chunks_exact_mut(4)
            .zip(words)
        {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
    }
    output
}

/// The number of rounds of Rijndael with a 256-bit block and a 256-bit key: Nr = 14.
pub const rijndael256Rounds: usize = 14;

/// Puts two 256-bit Rijndael blocks, each as eight little-endian words, into the bitsliced
/// form of `encryptFourBlocks`.
///
/// The form holds four 128-bit blocks of four columns. Here the even columns of the first
/// block take the place of block 0, those of the second block the place of block 1, and the
/// odd columns the places of blocks 2 and 3. Byte `r` of column `c` of block `b` is then bit
/// `16 r + 2 c + b` of each word, so the four rows stay in the four 16-bit lanes, and the
/// substitution and `mixColumns` of AES apply to the eight columns unchanged.
fn rijndael256Bitsliced(first: &[u32; 8], second: &[u32; 8]) -> [u64; 8] {
    let mut q = [0u64; 8];
    let places = [(first, 0, 0), (second, 0, 1), (first, 1, 2), (second, 1, 3)];
    for (words, firstColumn, place) in places {
        let columns = [
            words[firstColumn],
            words[firstColumn + 2],
            words[firstColumn + 4],
            words[firstColumn + 6],
        ];
        let (low, high) = interleaveIn(&columns);
        q[place] = low;
        q[place + 4] = high;
    }
    orthogonalize(&mut q);
    q
}

/// The two 256-bit Rijndael blocks, as eight little-endian words each, of the bitsliced form
/// of `rijndael256Bitsliced`.
fn rijndael256Blocks(mut q: [u64; 8]) -> [[u32; 8]; 2] {
    orthogonalize(&mut q);
    let mut blocks = [[0u32; 8]; 2];
    for (block, firstColumn, place) in [(0, 0, 0), (1, 0, 1), (0, 1, 2), (1, 1, 3)] {
        let columns = interleaveOut(q[place], q[place + 4]);
        for (index, word) in columns.into_iter().enumerate() {
            blocks[block][firstColumn + 2 * index] = word;
        }
    }
    blocks
}

/// The ShiftRows of Rijndael with eight columns: row `r` turns left by 0, 1, 3 and 4 columns,
/// the offsets C1 = 1, C2 = 3 and C3 = 4 of the Rijndael proposal for Nb = 8. A column step is
/// two bits of the 16-bit lane of a row.
fn shiftRows256(q: &mut [u64; 8]) {
    for word in q.iter_mut() {
        let x = *word;
        *word = (x & 0x000000000000FFFF)
            + ((x & 0x00000000FFFC0000) >> 2)
            + ((x & 0x0000000000030000) << 14)
            + ((x & 0x0000FFC000000000) >> 6)
            + ((x & 0x0000003F00000000) << 10)
            + ((x & 0xFF00000000000000) >> 8)
            + ((x & 0x00FF000000000000) << 8);
    }
}

/// The round keys of Rijndael with a 256-bit block and a 256-bit key, in the bitsliced form
/// of two blocks: eight words for each of the 15 round keys.
///
/// The key expansion is the one of the Rijndael proposal for Nk = Nb = 8. It is the expansion
/// of AES-256, continued to 120 words, so it substitutes the word after each round constant
/// and the fourth word of each group of eight.
pub fn rijndael256RoundKeys(key: &[u8; 32]) -> [u64; 120] {
    let totalWords = 8 * (rijndael256Rounds + 1);
    let mut schedule = [0u32; 120];
    decodeLittleEndian(key, &mut schedule[..8]);
    for index in 8..totalWords {
        let mut temporary = schedule[index - 1];
        if index % 8 == 0 {
            temporary = substituteWord(temporary.rotate_right(8)) ^ roundConstants[index / 8 - 1];
        } else if index % 8 == 4 {
            temporary = substituteWord(temporary);
        }
        schedule[index] = schedule[index - 8] ^ temporary;
    }
    let mut roundKeys = [0u64; 120];
    for (words, roundKey) in schedule.chunks_exact(8).zip(roundKeys.chunks_exact_mut(8)) {
        let words: &[u32; 8] = words.try_into().expect("eight words");
        roundKey.copy_from_slice(&rijndael256Bitsliced(words, words));
    }
    roundKeys
}

/// Encrypts two 256-bit blocks with Rijndael with a 256-bit block and the round keys of
/// `rijndael256RoundKeys`, and returns the 64 bytes of the two ciphertexts.
pub fn encryptTwoRijndael256Blocks(blocks: &[u8; 64], roundKeys: &[u64; 120]) -> [u8; 64] {
    let mut first = [0u32; 8];
    let mut second = [0u32; 8];
    decodeLittleEndian(&blocks[..32], &mut first);
    decodeLittleEndian(&blocks[32..], &mut second);
    let mut q = rijndael256Bitsliced(&first, &second);
    addRoundKey(&mut q, &roundKeys[..8]);
    for round in 1..rijndael256Rounds {
        substitute(&mut q);
        shiftRows256(&mut q);
        mixColumns(&mut q);
        addRoundKey(&mut q, &roundKeys[round * 8..round * 8 + 8]);
    }
    substitute(&mut q);
    shiftRows256(&mut q);
    addRoundKey(&mut q, &roundKeys[rijndael256Rounds * 8..]);
    let mut output = [0u8; 64];
    for (block, chunk) in rijndael256Blocks(q).iter().zip(output.chunks_exact_mut(32)) {
        for (word, bytes) in block.iter().zip(chunk.chunks_exact_mut(4)) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{rijndael256Bitsliced, rijndael256Blocks, shiftRows256, substituteWord};

    /// The AES S-box of FIPS 197, figure 7, written by hand from the standard.
    const substitutionBox: [u8; 256] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
        0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
        0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
        0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
        0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
        0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
        0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
        0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
        0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
        0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
        0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1,
        0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16,
    ];

    /// The bitsliced S-box circuit gives the table value for each of the 256 input bytes, in
    /// each of the four byte positions of a word.
    #[test]
    fn bitslicedSubstitutionMatchesTheTableForEveryByte() {
        for value in 0..=255u8 {
            for position in 0..4 {
                let word = u32::from(value) << (8 * position);
                let expected = u32::from(substitutionBox[value as usize]) << (8 * position);
                let zeroImage = u32::from(substitutionBox[0]);
                let others = (0..4)
                    .filter(|other| *other != position)
                    .fold(0u32, |sum, other| sum | (zeroImage << (8 * other)));
                assert_eq!(
                    substituteWord(word),
                    expected | others,
                    "byte {value:#04x} at position {position}"
                );
            }
        }
    }

    /// Two blocks of eight words whose bytes are all different.
    fn distinctBlocks() -> ([u32; 8], [u32; 8]) {
        let word = |base: u32| {
            u32::from_le_bytes([base as u8, base as u8 + 1, base as u8 + 2, base as u8 + 3])
        };
        (
            core::array::from_fn(|column| word(4 * column as u32)),
            core::array::from_fn(|column| word(128 + 4 * column as u32)),
        )
    }

    #[test]
    fn eachRijndael256ByteIsBit16RowPlus2ColumnPlusBlockOfEachWord() {
        for block in 0..2 {
            for column in 0..8 {
                for row in 0..4 {
                    let mut words = [[0u32; 8]; 2];
                    words[block][column] = 1 << (8 * row);
                    let q = rijndael256Bitsliced(&words[0], &words[1]);
                    // The byte 1 has only bit 0 set, so only the word of bit 0 holds it.
                    assert_eq!(q[0], 1u64 << (16 * row + 2 * column + block));
                    assert!(q[1..].iter().all(|word| *word == 0));
                }
            }
        }
        let (first, second) = distinctBlocks();
        assert_eq!(
            rijndael256Blocks(rijndael256Bitsliced(&first, &second)),
            [first, second]
        );
    }

    #[test]
    fn rijndael256ShiftRowsTurnsTheRowsBy0And1And3And4Columns() {
        let (first, second) = distinctBlocks();
        let mut q = rijndael256Bitsliced(&first, &second);
        shiftRows256(&mut q);
        let shifted = rijndael256Blocks(q);
        // State byte (row, column) of a block is byte `row` of word `column`, and ShiftRows
        // takes the new byte (row, column) from (row, column + offset) of the old state.
        let offsets = [0, 1, 3, 4];
        for (old, new) in [first, second].iter().zip(&shifted) {
            for (row, offset) in offsets.iter().enumerate() {
                for (column, word) in new.iter().enumerate() {
                    let source = (column + offset) % 8;
                    assert_eq!(
                        word.to_le_bytes()[row],
                        old[source].to_le_bytes()[row],
                        "row {row}, column {column}"
                    );
                }
            }
        }
    }
}
