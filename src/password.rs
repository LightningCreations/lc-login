use std::io::Write;

use bytemuck::{Pod, Zeroable};
use zeroize::Zeroizing;

pub mod algorithms {
    pub const SHA_224: u8 = 0;
    pub const SHA_256: u8 = 1;
    pub const SHA_384: u8 = 2;
    pub const SHA_512: u8 = 3;

    #[cfg(feature = "sha512_t")]
    pub const SHA_512_224: u8 = 6;
    #[cfg(feature = "sha512_t")]
    pub const SHA_512_256: u8 = 7;
    #[cfg(feature = "sha3")]
    pub const USE_SHA3: u8 = 8;

    #[cfg(feature = "blake2")]
    pub const BLAKE2B: u8 = 16;

    pub const DISABLED: u8 = 0xFF;
}

pub mod salting {
    pub const XOR: u8 = 0;
    pub const CONCAT: u8 = 1;
    pub const HMAC: u8 = 2;

    pub const DISABLED: u8 = 0x1F;
    pub const MASK: u8 = 0x1F;
    pub const ROUNDS_SHIFT: u8 = 5;
    pub const ROUNDS_MASK: u8 = 0xE0;
}

#[derive(Pod, Zeroable, Copy, Clone, Debug)]
#[repr(C)]
pub struct PasswordHeader {
    pub version: u16,
    pub algorithm: u8,
    pub salt_and_repetition: u8,
    pub salt_size: u32,
    pub expiry_seconds: u64,
}

impl Default for PasswordHeader {
    fn default() -> Self {
        Self {
            version: INVALID_VERSION,
            algorithm: algorithms::DISABLED,
            salt_and_repetition: salting::DISABLED | salting::ROUNDS_MASK,
            salt_size: 0xFFFFFFFF,
            expiry_seconds: 0,
        }
    }
}

pub const CURRENT_VERSION: u16 = 0;

pub const INVALID_VERSION: u16 = 0xFFFF;

pub const DEFAULT_ALGORITHM: u8 = algorithms::SHA_512;
pub const DEFAULT_SALT: u8 = salting::CONCAT;
pub const DEFAULT_ROUNDS: u8 = 4 << 5;

pub fn write_password<W: Write>(
    passwd: &str,
    salt: &[u8],
    algorithm: u8,
    salt_and_repetition: u8,
    mut w: W,
) -> std::io::Result<()> {
    let salt_method = salt_and_repetition & salting::MASK;
    let rounds =
        1u32 << (10 + (salt_and_repetition & salting::ROUNDS_MASK >> salting::ROUNDS_SHIFT));
    let mut input = passwd.as_bytes();
    let mut output = Zeroizing::new([0u8; 64]);
    for _ in 0..rounds {
        let size = input.len() + (32 - (input.len() % 32)) % 32 + salt.len();
        let mut bytes = Zeroizing::new(Vec::with_capacity(size));
        bytes.extend_from_slice(input);
        match salt_method {
            salting::XOR => {
                for i in 0..bytes.len() {
                    bytes[i] ^= salt[i % salt.len()];
                }
            }
            salting::CONCAT => {
                bytes.extend_from_slice(salt);
            }
            salting::HMAC => todo!("hmac is not implemented yet"),
            _ => panic!("Unsupported algorithm"),
        }
        let mut output: &mut [u8] = &mut *output;
        match algorithm {
            algorithms::SHA_224 => {
                output = &mut output[0..28];
                output.copy_from_slice(&openssl::sha::sha224(&bytes))
            }
            algorithms::SHA_256 => {
                output = &mut output[0..32];
                output.copy_from_slice(&openssl::sha::sha256(&bytes))
            }
            algorithms::SHA_384 => {
                output = &mut output[0..48];
                output.copy_from_slice(&openssl::sha::sha384(&bytes))
            }
            algorithms::SHA_512 => {
                output = &mut output[0..64];
                output.copy_from_slice(&openssl::sha::sha512(&bytes))
            }
            #[cfg(feature = "sha512_t")]
            algorithms::SHA_512_224 => todo!("lc-login does not yet support SHA-512/224"),
            #[cfg(feature = "sha512_t")]
            algorithms::SHA_512_256 => todo!("lc-login does not yet support SHA-512/256"),
            #[cfg(feature = "sha3")]
            x if (x & algorithms::USE_SHA3) != 0 => todo!("lc-login does not yet support SHA3"),
            #[cfg(feature = "blake2")]
            algorithms::BLAKE2B => todo!("lc-login does not yet support Blake2"),
            _ => panic!("unknown alogrithm"),
        }
        input = output;
    }
    w.write_all(input)?;

    Ok(())
}
