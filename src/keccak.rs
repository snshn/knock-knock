//! Keccak-256 (as used by Ethereum, i.e. original Keccak padding, not SHA3-256's),
//! implemented here to avoid pulling in a crate just for hashing a few short strings.

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// Rotation offsets and lane order for the combined rho and pi steps
const ROTATIONS: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
const PI_LANES: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// 256-bit output means 1088-bit (136-byte) rate
const RATE: usize = 136;

/// Keccak-f[1600] permutation
fn keccak_f(state: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        // Theta
        let mut columns = [0u64; 5];
        for (x, column) in columns.iter_mut().enumerate() {
            *column = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d: u64 = columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        // Rho and pi
        let mut current: u64 = state[1];
        for (&lane, &rotation) in PI_LANES.iter().zip(ROTATIONS.iter()) {
            let next: u64 = state[lane];
            state[lane] = current.rotate_left(rotation);
            current = next;
        }

        // Chi
        for y in 0..5 {
            let row: [u64; 5] = [
                state[5 * y],
                state[5 * y + 1],
                state[5 * y + 2],
                state[5 * y + 3],
                state[5 * y + 4],
            ];
            for x in 0..5 {
                state[5 * y + x] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }

        // Iota
        state[0] ^= round_constant;
    }
}

/// Sponge construction with 256-bit output; `padding` is the domain separation byte
/// (0x01 for original Keccak, 0x06 for SHA3)
fn sponge_256(data: &[u8], padding: u8) -> [u8; 32] {
    let mut state = [0u64; 25];

    let absorb = |state: &mut [u64; 25], block: &[u8]| {
        for (lane, chunk) in state.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(chunk.try_into().expect("chunk of 8 bytes"));
        }
        keccak_f(state);
    };

    let mut blocks = data.chunks_exact(RATE);
    for block in &mut blocks {
        absorb(&mut state, block);
    }

    // Pad the last (partial) block
    let remainder: &[u8] = blocks.remainder();
    let mut last_block = [0u8; RATE];
    last_block[..remainder.len()].copy_from_slice(remainder);
    last_block[remainder.len()] ^= padding;
    last_block[RATE - 1] ^= 0x80;
    absorb(&mut state, &last_block);

    let mut output = [0u8; 32];
    for (chunk, lane) in output.chunks_exact_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }

    output
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    sponge_256(data, 0x01)
}

#[cfg(test)]
pub(crate) fn sha3_256(data: &[u8]) -> [u8; 32] {
    sponge_256(data, 0x06)
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256_test_vectors() {
        assert_eq!(
            to_hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        // ENS label hash of "eth" (EIP-137)
        assert_eq!(
            to_hex(&keccak256(b"eth")),
            "4f5b812789fc606be1b3b16908db13fc7a9adf7ca72641f84d75b47069d3d7f0"
        );
    }

    #[test]
    fn ethereum_function_selectors() {
        assert_eq!(to_hex(&keccak256(b"nameExpires(uint256)")[..4]), "d6e4fa86");
        assert_eq!(to_hex(&keccak256(b"available(uint256)")[..4]), "96e494e8");
        assert_eq!(to_hex(&keccak256(b"ownerOf(uint256)")[..4]), "6352211e");
    }

    #[test]
    fn ens_label_hash() {
        // Token ID of vitalik.eth
        assert_eq!(
            to_hex(&keccak256(b"vitalik")),
            "af2caa1c2ca1d027f1ac823b529d0a67cd144264b2789fa2ea4d63a67c7103cc"
        );
    }

    #[test]
    fn sha3_256_test_vectors() {
        assert_eq!(
            to_hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            to_hex(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn block_boundaries() {
        // Exactly one block, and one byte short of / over it
        assert_eq!(
            to_hex(&sha3_256(&[b'a'; 135])),
            "8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9"
        );
        assert_eq!(
            to_hex(&sha3_256(&[b'a'; 136])),
            "3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1"
        );
        assert_eq!(
            to_hex(&sha3_256(&[b'a'; 137])),
            "f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614"
        );
    }
}
