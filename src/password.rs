use fake_enum::fake_enum;

fake_enum! {
    #[repr(u8)]
    pub enum struct Algorithms{
        Sha2_224 = 0,
        Sha2_256 = 1,
        Sha2_384 = 2,
        Sha2_512 = 3,
        Sha2_384_224 = 4,
        Sha2_384_256 = 5,
        Sha2_512_224 = 6,
        Sha2_512_256 = 7,
        Sha3_224 = 8,
        Sha3_256 = 9,
        Sha3_384 = 10,
        Sha3_512 = 11,
        Sha3_384_224 = 12,
        Sha3_384_256 = 13,
        Sha3_512_224 = 14,
        Sha3_512_256 = 15,



        Disable = 0xFF,
    }
}

fake_enum! {
    #[repr(u8)]
    pub enum struct Salting{
        Xor = 0,
        Concat = 1,
        Hmac = 2,

        Disable = 0x3F
    }
}

pub const DEFAULT_ALGORITHM: Algorithms = Algorithms::Sha2_512;
pub const DEFAULT_SALTING: Salting = Salting::Hmac;
