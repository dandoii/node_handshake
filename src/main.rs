use crate::error::*;
use crate::messages::handshake::*;
use secp256k1::{PublicKey, SecretKey};
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

use crate::constants::*;
use crate::messages::message_types::{BitcoinMessage, HelloMessage};
use crate::messages::version::Version;
use crate::utils::*;

mod constants;
mod encryption;
mod error;
mod messages;
mod utils;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("NODE HANDSHAKE");
    let mut ip_add = String::new();
    let mut chain = String::new();
    println!("Input desired blockchain: bitcoin (b) ethereum (e)");
    io::stdin()
        .read_line(&mut chain)
        .expect("Failed to read IP address");
    println!("Please input the Node IP Address and Port in format ip:port :");
    io::stdin()
        .read_line(&mut ip_add)
        .expect("Failed to read IP address");
    let stream = match handle_connection(ip_add.trim()).await {
        Ok(s) => s,
        Err(_e) => panic!("Error connecting to node"),
    };
    println!("We finished connecting");
    if chain.trim() == "b" || chain.trim() == "bitcoin" {
        let _ = perform_btc_handshake(stream).await;
    } else {
        let mut pub_key = String::new();
        println!("Input desired node pub key");
        io::stdin()
            .read_line(&mut pub_key)
            .expect("Failed to read IP address");
        let id_decoded = hex::decode(pub_key.trim()).unwrap();
        let public_key = convert_to_public_key(&id_decoded).unwrap();
        let _ = perform_eth_handshake(stream, public_key).await;
    }

    println!("Handshake Complete");
}

async fn handle_connection(sock_addr: &str) -> Result<TcpStream> {
    let stream = match TcpStream::connect(sock_addr).await {
        Ok(s) => s,
        Err(e) => panic!("Failed to connect to node: {:?}", e),
    };
    return Ok(stream);
}

async fn perform_btc_handshake(mut stream: TcpStream) -> Result<i32> {
    let _ = perform_version_check(&mut stream).await;
    let _ = perform_verack_check(&mut stream).await;
    Ok(0)
}

async fn perform_version_check(stream: &mut TcpStream) -> Result<i32> {
    //first perform the version exchange
    let version = Version::new(
        PROTOCOL_VERSION,
        SocketAddrV4::new(Ipv4Addr::new(172, 219, 109, 121), 8333),
    );
    let checksum = calc_checksum(&version.to_rawmessage().expect("Error"));
    let check_u32 = u32::from_le_bytes(checksum);
    let magic_num = u32::from_le_bytes(MAGIC_BYTES);
    let message = BitcoinMessage::new(
        magic_num,
        VERSION_COMMAND,
        check_u32,
        version.to_rawmessage().expect("oof"),
    );
    // Send version message.
    stream.write_all(&message.to_bytes()).await?;

    let mut reader = BufReader::new(stream);
    let received_bytes = match reader.fill_buf().await {
        Ok(r) => r,
        Err(_e) => panic!("Unable to fill byte buffer"),
    };
    let received_n = received_bytes.len();
    let received_version = match BitcoinMessage::from_bytes(received_bytes) {
        Ok(r) => r,
        Err(e) => panic!("error matching message:{:?}", e),
    };
    let version_message = match Version::from_rawmessage(&received_version.payload) {
        Ok(v) => v,
        Err(_e) => panic!("Failed to extract version from raw message"),
    };
    println!(
        "Version received from target node:{:?}",
        version_message.protocol_version
    );
    if version.nonce == version_message.nonce {
        panic!("Nonce conflict");
    }

    reader.consume(received_n);
    Ok(0)
}

async fn perform_verack_check(stream: &mut TcpStream) -> Result<i32> {
    let check_verack = calc_checksum(&Vec::new());
    let check_verack_u32 = u32::from_le_bytes(check_verack);
    let magic_num = u32::from_le_bytes(MAGIC_BYTES);
    let verack_message =
        BitcoinMessage::new(magic_num, VERACK_COMMAND, check_verack_u32, Vec::new());
    let verack_sent = BitcoinMessage::to_bytes(&verack_message);
    stream.write_all(&verack_sent).await?;
    let mut reader = BufReader::new(stream);
    let received_bytes = reader.fill_buf().await?;
    let _received_n2 = received_bytes.len();
    let v_deserialised = BitcoinMessage::from_bytes(received_bytes)?;
    let resp = parse_btc_response(v_deserialised.get_command().to_vec());
    println!("Command received from node: {}", resp);
    println!("Deserialised Message:{:?}", v_deserialised);
    Ok(0)
}

async fn perform_eth_handshake(mut stream: TcpStream, node_public_key: PublicKey) -> Result<()> {
    println!("starting handshake...");
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

    let mut handshake = HandShake::new(private_key, node_public_key);

    let auth_encrypted = handshake.auth();
    stream.write(&auth_encrypted).await?;

    println!("Auth message send to target node");

    let mut buf = [0_u8; 1024];
    let resp = stream.read(&mut buf).await?;

    let mut bytes_used = 0u16;

    let decrypted = handshake.decrypt(&mut buf, &mut bytes_used)?;

    println!("Hello Response from Node:{:?}", decrypted);

    handshake.derive_secrets(decrypted)?;

    let hello_frame = handshake.hello_message();
    stream.write(&hello_frame).await?;

    let frame = handshake.read_frame(&mut buf[bytes_used as usize..resp])?;
    decode_hello_message(frame)?;

    Ok(())
}
