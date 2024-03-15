use crate::io::Error;
use crate::utils::*;
use rlp::{Decodable, Encodable, Rlp, RlpStream};
use secp256k1::PublicKey;

#[derive(Debug)]
pub struct BitcoinMessage {
    magic: u32,
    command: [u8; 12],
    length: u32,
    checksum: u32,
    pub payload: Vec<u8>,
}

//as defined at:
//https://github.com/ethereum/devp2p/blob/master/rlpx.md#hello-0x00
#[derive(Debug)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: PublicKey,
}

#[derive(Debug)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

impl BitcoinMessage {
    pub fn new(magic: u32, command: [u8; 12], checksum: u32, payload: Vec<u8>) -> Self {
        Self {
            magic,
            command,
            length: payload.len() as u32,
            checksum,
            payload,
        }
    }

    pub fn get_command(&self) -> [u8; 12] {
        self.command
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buff = Vec::new();
        buff.extend_from_slice(&self.magic.to_le_bytes());
        buff.extend_from_slice(&self.command);
        buff.extend_from_slice(&self.length.to_le_bytes());
        buff.extend_from_slice(&self.checksum.to_ne_bytes());
        buff.extend_from_slice(&self.payload);
        buff
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BitcoinMessage, Error> {
        let (magic, buff) = parse_frombytes_le::<u32>(&bytes.to_vec())?;
        let (cmd, buff) = read_drop_slice(&buff, 12)?;
        let command = <[u8; 12]>::try_from(cmd).unwrap();
        let (length, buff) = parse_frombytes_le::<u32>(&buff)?;
        let (checksum, payload) = parse_frombytes_le::<u32>(&buff)?;

        Ok(BitcoinMessage {
            magic,
            command,
            length,
            checksum,
            payload,
        })
    }
}

//Implement RLP ENCODING and DECODING for the ethereum message types
//https://docs.rs/etcommon-rlp/latest/rlp/trait.Encodable.html#tymethod.rlp_append
//Create a stream to add data modularly
impl Encodable for HelloMessage {
    fn rlp_append(&self, stream: &mut RlpStream) {
        let node_id = &self.id.serialize_uncompressed()[1..65];
        stream.begin_list(5);
        stream.append(&self.protocol_version);
        stream.append(&self.client_version);
        stream.append_list(&self.capabilities);
        stream.append(&self.port);
        stream.append(&node_id);
    }
}

//read data from a trusted RLP appended in order expected.
impl Decodable for HelloMessage {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        let protocol_version: usize = rlp.val_at(0)?;
        let client_version: String = rlp.val_at(1)?;
        let capabilities: Vec<Capability> = rlp.list_at(2)?;
        let port: u16 = rlp.val_at(3)?;
        let id: Vec<u8> = rlp.val_at(4)?;

        //id slice
        let mut slice = [0_u8; 65];
        slice[0] = 4;
        slice[1..].copy_from_slice(&id);
        let id = PublicKey::from_slice(&slice).unwrap();

        Ok(Self {
            protocol_version,
            client_version,
            capabilities,
            port,
            id,
        })
    }
}

impl Encodable for Capability {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream.begin_list(2);
        stream.append(&self.name);
        stream.append(&self.version);
    }
}

impl Decodable for Capability {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let name: String = rlp.val_at(0)?;
        let version: usize = rlp.val_at(1)?;

        Ok(Self { name, version })
    }
}
