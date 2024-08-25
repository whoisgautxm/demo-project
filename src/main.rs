// use ethers_core::types::{Signature, Address};
// use ethers_core::utils::keccak256;
// use ethers_core::abi::{encode, Token};
// use std::str::FromStr;
// use hex;

// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // Hard-coded signature values from the JSON
//     let r = "a0b9dfb1950d6dff952b0aee3fc869a3cabdb0c04630f6b7782b413b054dfedc";
//     let s = "066e6b323bb11263888f9448a3b2972ccfcf87259052bc252d2d46c0726ce8b5";
//     let v = 27;

//     // Original message from the JSON
//     let version: u16 = 2;
//     let schema = "0x1c12bac4f230477c87449a101f5f9d6ca1c492866355c0a5e27026753e5ebf40";
//     let recipient = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
//     let time: u64 = 1724268339;
//     let expiration_time: u64 = 0;
//     let ref_uid = "0x0000000000000000000000000000000000000000000000000000000000000000";
//     let revocable: bool = true;
//     let data = "0x67617574616d0000000000000000000000000000000000000000000000000000";
//     let salt = "0x536b9414d8491a764168a98aac09a61141e72f72afb6f635d6618bb075321684";

//     // Encode the message in the same format it was signed
//     let encoded_message = keccak256(encode(&[
//         Token::Uint(version.into()),
//         Token::FixedBytes(hex::decode(&schema[2..])?),
//         Token::Address(Address::from_str(recipient)?),
//         Token::Uint(time.into()),
//         Token::Uint(expiration_time.into()),
//         Token::FixedBytes(hex::decode(&ref_uid[2..])?),
//         Token::Bool(revocable),
//         Token::Bytes(hex::decode(&data[2..])?),
//         Token::FixedBytes(hex::decode(&salt[2..])?),
//     ]));

//     // Construct the Signature struct
//     let signature = Signature {
//         r: r.parse()?,
//         s: s.parse()?,
//         v: v as u64,
//     };

//     // Recover the signer address from the signature and message
//     let recovered_address = signature.recover(encoded_message)?;

//     // Print the recovered address
//     println!("Recovered Address: {:?}", recovered_address);

//     Ok(())
// }


use ethers_core::types::{Address, H256, U256 , Signature};
use ethers_core::types::transaction::eip712::EIP712Domain;
use ethers_core::abi::{encode, Token};
use ethers_core::utils::keccak256;
use hex::decode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Attest {
    version: u16,
    schema: H256,
    recipient: Address,
    time: u64,
    expiration_time: u64,
    revocable: bool,
    ref_uid: H256,
    data: Vec<u8>,
    salt: H256,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fill the EIP-712 domain
    let domain = EIP712Domain {
        name: Some("EAS Attestation".to_string()),
        version: Some("0.26".to_string()),
        chain_id: Some(U256::from_dec_str("11155111")?),
        verifying_contract: Some("0xC2679fBD37d54388Ce493F1DB75320D236e1815e".parse()?),
        salt: None, // Optional field; not present in the JSON
    };

    // Convert the hex string representing the data field to a byte array
    let hex_data = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003274687820666f7220657468657265756d2e2e2e616e642065766572797468696e6720796f7520617265206372656174696e670000000000000000000000000000";
    let data_bytes = decode(hex_data)?;

    // Fill the Attest struct
    let message = Attest {
        version: 2,
        schema: "0x3969bb076acfb992af54d51274c5c868641ca5344e1aacd0b1f5e4f80ac0822f".parse()?,
        recipient: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".parse()?,
        time: 1724055734,
        expiration_time: 0,
        revocable: true,
        ref_uid: "0x0000000000000000000000000000000000000000000000000000000000000000".parse()?,
        data: data_bytes,
        salt: "0x0efabb71696d2d46ef475b8a9c3fd9ab794aaaf7fe51b611d0ce70d33b1c3e66".parse()?,
    };

    // Generate the domain separator
    let domain_separator = domain.separator();

    // Encode the message hash
    let encoded_message = serde_json::to_vec(&message)?;
    let message_hash = keccak256(&encoded_message);

    // Combine domain separator and message hash
    let digest = keccak256(&[&domain_separator[..], &message_hash[..]].concat());

    // The signature from the JSON
    let r = "0x5c6e2fbdcc3f4eae1e83332ff58058f0f512d1c581c99360710e3c6a9cacd2db".parse()?;
    let s = "0x5d8778fb9ccf2e3a6f29fbba781573023ebba903fde86e30c59038f75a91d17c".parse()?;
    let v: u64 = 27;

    // The signer's address
    let signer = "0xa82082380585489B0456e15343C23809BC334709".parse::<Address>()?;

    // Verify the signature
    let recovered_signer = ethers_core::utils::recover(&digest, &r, &s, v)?;

    // Check if the recovered signer matches the expected signer
    if recovered_signer == signer {
        println!("Signature is valid!");
    } else {
        println!("Signature is invalid!");
    }

    Ok(())
}
