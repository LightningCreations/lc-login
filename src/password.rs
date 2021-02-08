use bytemuck::{Pod, Zeroable};

pub mod algorithms {
    pub const SHA_224: u8 = 0;
    pub const SHA_256: u8 = 1;
    pub const SHA_384: u8 = 2;
    pub const SHA_512: u8 = 3;
    pub const SHA_384_224: u8 = 4;
    pub const SHA_384_256: u8 = 5;
    pub const SHA_512_224: u8 = 6;
    pub const SHA_512_256: u8 = 7;
    pub const USE_SHA3: u8 = 8;

    pub const BLAKE2: u8 = 16;

    pub const DISABLED: u8 = 0xFF;
}

pub mod salting {
    pub const XOR: u8 = 0;
    pub const CONCAT: u8 = 1;
    pub const HMAC: u8 = 2;

    pub const DISABLED: u8 = 0x7F;
    pub const MASK: u8 = 0x7F;
    pub const ROUNDS_MASK: u8 = 0x80;
}

#[derive(Pod, Zeroable, Copy, Clone, Debug)]
#[repr(C)]
pub struct PasswordHeader {
    pub version: u16,
    pub algorithm: u8,
    pub salting_and_repetition: u8,
}
