use ethers_core::types::{Address, RecoveryMessage, Signature, H256, U256};
use ethers_core::utils::keccak256;
use ethers_core::abi::{encode, Token};
use ethers_core::utils::hex;
use ethers_core::types::transaction::eip712::EIP712Domain;
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

fn domain_separator(domain: &EIP712Domain, type_hash: H256) -> H256 {
    let encoded = encode(&[
        Token::FixedBytes(type_hash.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(domain.name.as_ref().unwrap().as_bytes()).to_vec()),
        Token::FixedBytes(keccak256(domain.version.as_ref().unwrap().as_bytes()).to_vec()),
        Token::Uint(domain.chain_id.unwrap()),
        Token::Address(domain.verifying_contract.unwrap()),
    ]);
    keccak256(&encoded).into()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fill the EIP-712 domain
    let domain = EIP712Domain {
        name: Some("EAS Attestation".to_string()),
        version: Some("0.26".to_string()),
        chain_id: Some(U256::from_dec_str("11155111")?),
        verifying_contract: Some("0xC2679fBD37d54388Ce493F1DB75320D236e1815e".parse()?),
        salt: None,
    };

    let eip712_domain_typehash: H256 = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ).into();

    // Generate the domain separator
    let i_domain_separator = domain_separator(&domain, eip712_domain_typehash);

    // Convert the hex string representing the data field to a byte array
    let hex_data = "67617574616d0000000000000000000000000000000000000000000000000000";
    let data = hex::decode(hex_data)?;

    let message = Attest {
        version: 2,
        schema: "0x1c12bac4f230477c87449a101f5f9d6ca1c492866355c0a5e27026753e5ebf40".parse()?,
        recipient: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".parse()?,
        time: 1724435715,
        expiration_time: 0,
        revocable: true,
        ref_uid: H256::zero(),
        data,
        salt: "0x8af354b397009a1070c1d958e1a3ce0ab6246bdc21ff3f862a42994c6fc2c1ba".parse()?,
    };

    // Define the type hash for the Message struct
    let message_typehash: H256 = keccak256(
        b"Attest(uint16 version,bytes32 schema,address recipient,uint64 time,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,bytes32 salt)"
    ).into();

    // Encode the message
    let encoded_message = encode(&[
        Token::FixedBytes(message_typehash.as_bytes().to_vec()),
        Token::Uint(U256::from(message.version)),
        Token::FixedBytes(message.schema.as_bytes().to_vec()),
        Token::Address(message.recipient),
        Token::Uint(U256::from(message.time)),
        Token::Uint(U256::from(message.expiration_time)),
        Token::Bool(message.revocable),
        Token::FixedBytes(message.ref_uid.as_bytes().to_vec()),
        Token::FixedBytes(keccak256(&message.data).to_vec()),
        Token::FixedBytes(message.salt.as_bytes().to_vec()),
    ]);

    // Generate the hashed message
    let hashed_message = keccak256(&encoded_message);

    let prefix: [u8; 1] = [0x19];
    let eip712_version: [u8; 1] = [0x01]; // EIP-712 is version 1 of EIP-191

    // Combine the prefix, eip712_version, hashStructOfDomainSeparator, and hashedMessage
    let mut combined = Vec::new();
    combined.extend_from_slice(&prefix);
    combined.extend_from_slice(&eip712_version);
    combined.extend_from_slice(&i_domain_separator.to_fixed_bytes());
    combined.extend_from_slice(&hashed_message);

    // Generate the final digest
    let digest = keccak256(&combined).into();

    // Define the signature parts
    let signature = Signature {
        r: "0x5f19cd73e4fb54a8d014150f02068f941fffde1a7382d94265725aa7a8c30861".parse()?,
        s: "0x031ccb397e2e49c76a4e1f070c4c8ed15e59dad4857429c9bd1e8f9a9b0a0846".parse()?,
        v: 27,
    };
    let recovey_message = RecoveryMessage::Hash(digest);

    // Recover the address from the signature
    let recovered_address = signature.recover(recovey_message)?;

    println!("Recovered address: {:?}", recovered_address);

    Ok(())
}