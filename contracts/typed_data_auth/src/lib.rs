#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String, crypto::Signature};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u32,
    pub verifying_contract: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transfer {
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

#[contract]
pub struct TypedDataAuth;

#[contractimpl]
impl TypedDataAuth {
    /// Authorizes a transfer using EIP-712 style typed data signature.
    /// Verifies the signature and requires auth from the signer.
    pub fn authorize_transfer(
        env: Env,
        domain: Domain,
        transfer: Transfer,
        signature: Signature,
        signer: Address,
    ) {
        let domain_hash = Self::domain_separator_hash(&env, &domain);
        let struct_hash = Self::struct_hash(&env, &transfer);
        let message_hash = Self::message_hash(&env, &domain_hash, &struct_hash);

        env.crypto().verify(&signature, &message_hash, &signer);

        // Require authorization from the signer
        signer.require_auth();

        // Log the successful authorization (optional)
        env.events().publish(("transfer_authorized",), (signer, transfer.from, transfer.to, transfer.amount));
    }

    /// Computes the domain separator hash.
    fn domain_separator_hash(env: &Env, domain: &Domain) -> BytesN<32> {
        let type_hash = env.crypto().sha256(
            &env.bytes(b"EIP712Domain(string name,string version,u32 chainId,Address verifyingContract)")
        );
        let name_hash = env.crypto().sha256(&env.bytes(domain.name.as_bytes()));
        let version_hash = env.crypto().sha256(&env.bytes(domain.version.as_bytes()));
        let chain_id_bytes = domain.chain_id.to_be_bytes();
        let verifying_contract_bytes = domain.verifying_contract.to_raw().to_be_bytes();

        let mut data = Bytes::new(env);
        data.extend_from_slice(&type_hash);
        data.extend_from_slice(&name_hash);
        data.extend_from_slice(&version_hash);
        data.extend_from_slice(&chain_id_bytes);
        data.extend_from_slice(&verifying_contract_bytes);

        env.crypto().sha256(&data)
    }

    /// Computes the struct hash for Transfer.
    fn struct_hash(env: &Env, transfer: &Transfer) -> BytesN<32> {
        let type_hash = env.crypto().sha256(
            &env.bytes(b"Transfer(address from,address to,int128 amount)")
        );
        let from_bytes = transfer.from.to_raw().to_be_bytes();
        let to_bytes = transfer.to.to_raw().to_be_bytes();
        let amount_bytes = transfer.amount.to_be_bytes();

        let mut data = Bytes::new(env);
        data.extend_from_slice(&type_hash);
        data.extend_from_slice(&from_bytes);
        data.extend_from_slice(&to_bytes);
        data.extend_from_slice(&amount_bytes);

        env.crypto().sha256(&data)
    }

    /// Computes the final message hash.
    fn message_hash(
        env: &Env,
        domain_separator: &BytesN<32>,
        struct_hash: &BytesN<32>,
    ) -> BytesN<32> {
        let prefix = env.bytes(&[0x19, 0x01]);
        let mut data = Bytes::new(env);
        data.extend_from_slice(&prefix);
        data.extend_from_slice(domain_separator);
        data.extend_from_slice(struct_hash);

        env.crypto().sha256(&data)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::{Address as _, BytesN as _};
    use soroban_sdk::crypto::Signature;

    #[test]
    fn test_domain_separator_hash() {
        let env = Env::default();
        let contract_address = Address::generate(&env);
        let domain = Domain {
            name: String::from_str(&env, "TestContract"),
            version: String::from_str(&env, "1.0"),
            chain_id: 1,
            verifying_contract: contract_address,
        };

        let hash = TypedDataAuth::domain_separator_hash(&env, &domain);
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_struct_hash() {
        let env = Env::default();
        let from = Address::generate(&env);
        let to = Address::generate(&env);
        let transfer = Transfer {
            from: from.clone(),
            to: to.clone(),
            amount: 1000,
        };

        let hash = TypedDataAuth::struct_hash(&env, &transfer);
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_message_hash() {
        let env = Env::default();
        let domain_hash = BytesN::from_array(&env, &[1u8; 32]);
        let struct_hash = BytesN::from_array(&env, &[2u8; 32]);

        let message_hash = TypedDataAuth::message_hash(&env, &domain_hash, &struct_hash);
        assert!(!message_hash.is_zero());
    }

    // Note: Full integration test with signature verification would require
    // generating valid signatures, which is complex in unit tests.
    // This should be tested in integration tests with actual keypairs.
}

mod test;