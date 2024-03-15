use secp256k1::PublicKey;

use crate::constants::CHECKSUM_SIZE;
use crate::error::*;
use crate::HelloMessage;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::time::UNIX_EPOCH;

pub fn parse_btc_response(r: Vec<u8>) -> String {
    if r == [115, 101, 110, 100, 99, 109, 112, 99, 116, 0, 0, 0] {
        "sendcmpt".to_string()
    } else if r == [118, 101, 114, 97, 99, 107, 0, 0, 0, 0, 0, 0] {
        "verack".to_string()
    } else {
        "unknown node response".to_string()
    }
}

pub fn decode_hello_message(f: Vec<u8>) -> Result<()> {
    let m_id: u8 = rlp::decode(&[f[0]])?;
    if m_id == 0 {
        let h: HelloMessage = rlp::decode(&f[1..])?;
        println!("Hello message received from target node:\n{:?}", h);
    }

    Ok(())
}

pub fn convert_to_public_key(data: &[u8]) -> Result<PublicKey> {
    let mut s = [4_u8; 65];
    s[1..].copy_from_slice(data);

    let public_key =
        PublicKey::from_slice(&s).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

    Ok(public_key)
}
pub fn calc_checksum(data: &[u8]) -> [u8; CHECKSUM_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(hash);
    let hash = hasher.finalize();

    let mut buf = [0u8; CHECKSUM_SIZE];
    buf.clone_from_slice(&hash[..CHECKSUM_SIZE]);

    buf
}

pub fn generate_random_nonce() -> u64 {
    let mut rng = thread_rng();
    rng.gen::<u64>()
}

pub fn calculate_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
//Little and Big Endian conversion
//as defined at https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
pub fn parse_frombytes_be<'a, T>(buff: &Vec<u8>) -> Result<(T, Vec<u8>), std::io::Error>
where
    T: FromEndian + Sized,
{
    let size = core::mem::size_of::<T>();
    match read_drop_slice(buff, size) {
        Ok((res, remaining)) => Ok((FromEndian::from_be(&res), remaining)),
        Err(e) => Err(e),
    }
}

pub fn parse_frombytes_le<'a, T>(buff: &Vec<u8>) -> Result<(T, Vec<u8>), std::io::Error>
where
    T: FromEndian + Sized,
{
    let size = core::mem::size_of::<T>();
    match read_drop_slice(buff, size) {
        Ok((res, remaining)) => Ok((FromEndian::from_le(&res), remaining)),
        Err(e) => Err(e),
    }
}

pub fn read_drop_slice(buff: &Vec<u8>, size: usize) -> Result<(&[u8], Vec<u8>), std::io::Error> {
    if buff.len() >= size {
        Ok((&buff[0..size], buff[size..].to_vec()))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Buffer too small",
        ))
    }
}

pub trait FromEndian {
    fn from_be(msg: &[u8]) -> Self
    where
        Self: Sized;
    fn from_le(msg: &[u8]) -> Self
    where
        Self: Sized;
}

impl FromEndian for i32 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(msg);
        i32::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(msg);
        i32::from_le_bytes(bytes)
    }
}

impl FromEndian for i64 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(msg);
        i64::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(msg);
        i64::from_le_bytes(bytes)
    }
}

impl FromEndian for u16 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(msg);
        u16::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(msg);
        u16::from_le_bytes(bytes)
    }
}

impl FromEndian for u32 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(msg);
        u32::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(msg);
        u32::from_le_bytes(bytes)
    }
}

impl FromEndian for u64 {
    fn from_be(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(msg);
        u64::from_be_bytes(bytes)
    }
    fn from_le(msg: &[u8]) -> Self {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(msg);
        u64::from_le_bytes(bytes)
    }
}
