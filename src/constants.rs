//List of constants for use as defined by protocol
//https://github.com/bitcoin/bitcoin/blob/88b1229c134fa006d9a57e908ebebec944419347/src/protocol.h for reference

pub const CHECKSUM_SIZE: usize = 4;

pub const MAGIC_BYTES: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

pub const PROTOCOL_VERSION: i32 = 70016;

pub const VERSION_COMMAND: [u8; 12] = *b"version\0\0\0\0\0";

pub const VERACK_COMMAND: [u8; 12] = *b"verack\0\0\0\0\0\0";

//list of constants used for ethereum communication
//header used for the hello message
pub const ZERO_HEADER: &[u8; 3] = &[194, 128, 128];

pub const ETH_PROTOCOL_VERSION: usize = 5;
