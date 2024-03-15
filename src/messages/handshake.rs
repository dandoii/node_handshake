use crate::encryption::{ecies::ECIES, hmac::HMac};
use crate::HelloMessage;
use crate::{
    constants::{ETH_PROTOCOL_VERSION, ZERO_HEADER},
    error::{Error, Result},
};
use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use ethereum_types::{H128, H256};
use rlp::{Rlp, RlpStream};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::Digest;
use sha3::Keccak256;

//define types for block ciphers
pub type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;

pub struct HandShake {
    pub ecies_data: ECIES,
    pub aes_secret_key: Option<H256>,
    pub shared_secret_key: Option<H256>,
    pub mac_secret_key: Option<H256>,
    pub ingress_h_mac: Option<HMac>,
    pub egress_h_mac: Option<HMac>,
    pub ingress_aes: Option<Aes256Ctr64BE>,
    pub egress_aes: Option<Aes256Ctr64BE>,
}

impl HandShake {
    pub fn new(private_key: SecretKey, remote_public_key: PublicKey) -> Self {
        HandShake {
            ecies_data: ECIES::new(private_key, remote_public_key),
            aes_secret_key: None,
            shared_secret_key: None,
            mac_secret_key: None,
            ingress_h_mac: None,
            egress_h_mac: None,
            ingress_aes: None,
            egress_aes: None,
        }
    }

    fn gen_signature(&self) -> [u8; 65] {
        let m = self.ecies_data.shared_key ^ self.ecies_data.nonce;
        let message = &secp256k1::Message::from_slice(m.as_bytes()).unwrap();
        let (recipient_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(message, &self.ecies_data.ephemeral_key)
            .serialize_compact();
        let mut signature: [u8; 65] = [0; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = recipient_id.to_i32() as u8;

        signature
    }

    pub fn encrypt(&self, data_in: BytesMut, data_out: &mut BytesMut) -> Result<usize> {
        self.ecies_data.encrypt(data_in, data_out)
    }

    pub fn auth(&mut self) -> BytesMut {
        let signature = self.gen_signature();

        let full_pub_key = self.ecies_data.public_key.serialize_uncompressed();
        let public_key = &full_pub_key[1..];

        let mut stream = RlpStream::new_list(4);
        stream.append(&&signature[..]);
        stream.append(&public_key);
        stream.append(&self.ecies_data.nonce.as_bytes());
        stream.append(&ETH_PROTOCOL_VERSION);

        let auth_body = stream.out();

        let mut buf = BytesMut::default();
        let _encrypted_len = self.encrypt(auth_body, &mut buf);

        self.ecies_data.auth_mess = Some(Bytes::copy_from_slice(&buf[..]));

        buf
    }

    pub fn decrypt<'a>(
        &mut self,
        data_in: &'a mut [u8],
        read_bytes: &mut u16,
    ) -> Result<&'a mut [u8]> {
        self.ecies_data.decrypt(data_in, read_bytes)
    }

    fn create_hash(&self, inputs: &[&[u8]]) -> H256 {
        let mut hasher = Keccak256::new();

        for input in inputs {
            hasher.update(input)
        }

        H256::from(hasher.finalize().as_ref())
    }

    pub fn hello_message(&mut self) -> BytesMut {
        let msg = HelloMessage {
            protocol_version: ETH_PROTOCOL_VERSION,
            client_version: "hello".to_string(),
            capabilities: vec![],
            port: 0,
            id: self.ecies_data.public_key,
        };

        let mut encoded_hello = BytesMut::default();
        encoded_hello.extend_from_slice(&rlp::encode(&0_u8));
        encoded_hello.extend_from_slice(&rlp::encode(&msg));

        self.write_frame(&encoded_hello)
    }

    fn write_frame(&mut self, data: &[u8]) -> BytesMut {
        let mut buf = [0; 8];
        let n_bytes = 3;
        BigEndian::write_uint(&mut buf, data.len() as u64, n_bytes);

        let mut header_buf = [0_u8; 16];
        header_buf[..3].copy_from_slice(&buf[..3]);
        header_buf[3..6].copy_from_slice(ZERO_HEADER);

        let egress_aes = self.egress_aes.as_mut().unwrap();
        let egress_mac = self.egress_h_mac.as_mut().unwrap();

        egress_aes.apply_keystream(&mut header_buf);
        egress_mac.compute_header(&header_buf);

        let mac = egress_mac.digest();

        let mut out = BytesMut::default();
        out.reserve(32);
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(mac.as_bytes());

        let mut len = data.len();
        if len % 16 > 0 {
            len = (len / 16 + 1) * 16;
        }

        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        egress_aes.apply_keystream(encrypted);
        egress_mac.compute_frame(encrypted);
        let mac = egress_mac.digest();

        out.extend_from_slice(mac.as_bytes());

        out
    }

    pub fn derive_secrets(&mut self, ack_body: &[u8]) -> Result<()> {
        let rlp = Rlp::new(ack_body);

        let recipient_ephemeral_pubk_raw: Vec<_> = rlp.val_at(0)?;

        let mut buf = [4_u8; 65];
        buf[1..].copy_from_slice(&recipient_ephemeral_pubk_raw);
        let recipient_ephemeral_pubk =
            PublicKey::from_slice(&buf).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

        // recipient nonce
        let recipient_nonce_raw: Vec<_> = rlp.val_at(1)?;
        let recipient_nonce = H256::from_slice(&recipient_nonce_raw);

        //ignore any version differences

        // ephemeral-key
        let ephemeral_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(
                &recipient_ephemeral_pubk,
                &self.ecies_data.ephemeral_key,
            )[..32],
        );

        let keccak_nonce =
            self.create_hash(&[recipient_nonce.as_ref(), self.ecies_data.nonce.as_ref()]);
        let shared_secret = self.create_hash(&[ephemeral_key.as_ref(), keccak_nonce.as_ref()]);
        let aes_secret = self.create_hash(&[ephemeral_key.as_ref(), shared_secret.as_ref()]);
        let mac_secret = self.create_hash(&[ephemeral_key.as_ref(), aes_secret.as_ref()]);

        // egress-mac
        let mut egress_mac = HMac::new(mac_secret);
        egress_mac.update((mac_secret ^ recipient_nonce).as_bytes());
        egress_mac.update(self.ecies_data.auth_mess.as_ref().unwrap());

        // ingress-mac
        let mut ingress_mac = HMac::new(mac_secret);
        ingress_mac.update((mac_secret ^ self.ecies_data.nonce).as_bytes());
        ingress_mac.update(self.ecies_data.auth_received.as_ref().unwrap());

        let iv = H128::default();

        self.aes_secret_key = Some(aes_secret);
        self.mac_secret_key = Some(mac_secret);
        self.shared_secret_key = Some(shared_secret);
        self.egress_h_mac = Some(egress_mac);
        self.ingress_h_mac = Some(ingress_mac);
        self.egress_aes = Some(Aes256Ctr64BE::new(
            aes_secret.as_ref().into(),
            iv.as_ref().into(),
        ));
        self.ingress_aes = Some(Aes256Ctr64BE::new(
            aes_secret.as_ref().into(),
            iv.as_ref().into(),
        ));

        Ok(())
    }
    pub fn read_frame(&mut self, buf: &mut [u8]) -> Result<Vec<u8>> {
        let (header_bytes, frame) = buf.split_at_mut(32);
        let (header, mac) = header_bytes.split_at_mut(16);
        let mac = H128::from_slice(mac);

        let ingress_h_mac = self.ingress_h_mac.as_mut().unwrap();
        let ingress_aes = self.ingress_aes.as_mut().unwrap();

        ingress_h_mac.compute_header(header);
        if mac != ingress_h_mac.digest() {
            return Err(Error::InvalidMac(mac));
        }

        ingress_aes.apply_keystream(header);

        let mut frame_size = BigEndian::read_uint(header, 3) + 16;
        let padding = frame_size % 16;
        if padding > 0 {
            frame_size += 16 - padding;
        }

        let (frame, _) = frame.split_at_mut(frame_size as usize);
        let (frame_data, frame_mac) = frame.split_at_mut(frame.len() - 16);
        let frame_mac = H128::from_slice(frame_mac);

        ingress_h_mac.compute_frame(frame_data);

        if frame_mac == ingress_h_mac.digest() {
            println!("\nHanshake success\nMAC IS VALID");
            println!("Frame Mac:{:?}", frame_mac);
            println!("Ingress Mac:{:?}", ingress_h_mac.digest());
        } else {
            return Err(Error::InvalidMac(frame_mac));
        }

        ingress_aes.apply_keystream(frame_data);

        Ok(frame_data.to_owned())
    }
}
