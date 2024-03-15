//implementation of the version message
//references used: https://en.bitcoin.it/wiki/Protocol_documentation#version
use crate::io::Error;
use crate::utils::*;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::BitAnd;

#[derive(Debug)]
pub struct Version {
    pub protocol_version: i32,
    pub service: u64,
    pub timestamp: i64,
    pub addr_recv: SocketAddrV4,
    pub addr_from: SocketAddrV4,
    pub nonce: u64,
    pub user_agent: String,
    pub start_height: i32,
}

impl Version {
    pub fn new(protocol_version: i32, addr_recv: SocketAddrV4) -> Self {
        let timestamp = calculate_timestamp();
        Version {
            protocol_version,
            service: 0x1,
            timestamp,
            addr_recv,
            addr_from: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080),
            nonce: generate_random_nonce(),
            user_agent: "".to_string(),
            start_height: 1,
        }
    }

    pub fn from_rawmessage(msg: &Vec<u8>) -> Result<Version, Error> {
        let (protocol_version, buff) = parse_frombytes_le::<i32>(msg)?;
        let (service, buff) = parse_frombytes_le::<u64>(&buff)?;
        let (timestamp, buff) = parse_frombytes_le::<i64>(&buff)?;
        let address = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8333);
        let add_from = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8333);
        let (nonce, _) = parse_frombytes_le::<u64>(&buff)?;

        Ok(Version {
            protocol_version,
            service,
            timestamp,
            addr_recv: address,
            addr_from: add_from,
            nonce,
            user_agent: "".to_string(),
            start_height: 1,
        })
    }

    pub fn to_rawmessage(&self) -> Result<Vec<u8>, Error> {
        let mut b: u64 = 0x0;
        b = b.bitand(*&0x1 as u64);
        let mut address_bytes = Self::netaddr_as_bytes(&b, &self.addr_recv);

        let mut buffer: Vec<u8> = vec![];
        buffer.extend_from_slice(&self.protocol_version.to_le_bytes());
        buffer.extend_from_slice(&b.to_le_bytes());
        buffer.extend_from_slice(&self.timestamp.to_le_bytes());
        buffer.append(&mut address_bytes);
        buffer.extend_from_slice(&[0x0_u8; 26]); // addr_from
        buffer.extend_from_slice(&self.nonce.to_le_bytes());
        buffer.extend_from_slice(&[0]); // user agent
        buffer.extend_from_slice(&self.start_height.to_le_bytes());
        buffer.extend_from_slice(&[0]);

        Ok(buffer)
    }

    fn netaddr_as_bytes(node_bitmask: &u64, address: &SocketAddrV4) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&node_bitmask.to_le_bytes());
        let ip_addr_bytes = address.ip().to_ipv6_compatible().octets();

        buffer.extend_from_slice(&ip_addr_bytes);
        buffer.extend_from_slice(&address.port().to_be_bytes());

        buffer
    }
}
