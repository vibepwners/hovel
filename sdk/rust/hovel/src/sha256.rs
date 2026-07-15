//! Dependency-free SHA-256 used only to verify protocol integrity digests.
//!
//! Hovel's zero-dependency Rust SDK cannot rely on a host crypto provider at
//! runtime. This module implements the fixed FIPS 180-4 compression function
//! so provider results can be checked before they cross the SDK boundary. It
//! is not exposed as a general cryptographic API and is never used for keys,
//! signatures, or randomness.

use std::fmt::Write as _;

const BITS_PER_BYTE: u64 = 8;
const WORD_BYTES: usize = 4;
const STATE_WORDS: usize = 8;
const BLOCK_BYTES: usize = 64;
const LENGTH_BYTES: usize = 8;
const MESSAGE_WORDS: usize = 16;
const SCHEDULE_WORDS: usize = 64;
const DIGEST_BYTES: usize = STATE_WORDS * WORD_BYTES;
const HEX_DIGEST_BYTES: usize = DIGEST_BYTES * 2;
const PADDING_MARKER: u8 = 0x80;

const INITIAL_STATE: [u32; STATE_WORDS] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND_CONSTANTS: [u32; SCHEDULE_WORDS] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

pub(crate) fn hex_digest(input: &[u8]) -> String {
    let mut out = String::with_capacity(HEX_DIGEST_BYTES);
    for byte in digest(input) {
        write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn digest(input: &[u8]) -> [u8; DIGEST_BYTES] {
    let bit_length = (input.len() as u64).wrapping_mul(BITS_PER_BYTE);
    let mut state = INITIAL_STATE;
    let mut blocks = input.chunks_exact(BLOCK_BYTES);
    for block in blocks.by_ref() {
        compress(&mut state, block);
    }

    let remainder = blocks.remainder();
    let mut final_blocks = [[0_u8; BLOCK_BYTES]; 2];
    final_blocks[0][..remainder.len()].copy_from_slice(remainder);
    final_blocks[0][remainder.len()] = PADDING_MARKER;
    let final_block_count = if remainder.len() + 1 + LENGTH_BYTES <= BLOCK_BYTES {
        1
    } else {
        2
    };
    final_blocks[final_block_count - 1][BLOCK_BYTES - LENGTH_BYTES..]
        .copy_from_slice(&bit_length.to_be_bytes());
    for block in final_blocks.iter().take(final_block_count) {
        compress(&mut state, block);
    }

    let mut output = [0_u8; DIGEST_BYTES];
    for (word, bytes) in state.iter().zip(output.chunks_exact_mut(WORD_BYTES)) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn compress(state: &mut [u32; STATE_WORDS], block: &[u8]) {
    let mut schedule = [0_u32; SCHEDULE_WORDS];
    for (word, bytes) in schedule
        .iter_mut()
        .take(MESSAGE_WORDS)
        .zip(block.chunks_exact(WORD_BYTES))
    {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for index in MESSAGE_WORDS..SCHEDULE_WORDS {
        let sigma0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let sigma1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (round_constant, word) in ROUND_CONSTANTS.iter().zip(schedule) {
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ ((!e) & g);
        let temporary1 = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(*round_constant)
            .wrapping_add(word);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temporary2 = sum0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temporary1);
        d = c;
        c = b;
        b = a;
        a = temporary1.wrapping_add(temporary2);
    }

    for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *word = word.wrapping_add(value);
    }
}
