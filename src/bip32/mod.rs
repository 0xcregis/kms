mod error;
mod prefix;
mod child_number;
mod private_key;
mod public_key;
mod derivation_path;
mod extended_key;

pub use child_number::ChildNumber;
pub use error::{Error,Result};
pub use prefix::Prefix;
pub use private_key::{PrivateKey, PrivateKeyBytes};
pub use public_key::{PublicKey, PublicKeyBytes};
pub use extended_key::{
    attrs::ExtendedKeyAttrs, private_key::ExtendedPrivateKey, public_key::ExtendedPublicKey,
    ExtendedKey,
};
pub use {
    extended_key::{private_key::XPrv, public_key::XPub}
};

pub use derivation_path::DerivationPath;



/// Chain code: extension for both private and public keys which provides an
/// additional 256-bits of entropy.
pub type ChainCode = [u8; KEY_SIZE];

/// Derivation depth.
pub type Depth = u8;

/// BIP32 key fingerprints.
pub type KeyFingerprint = [u8; 4];

/// BIP32 "versions": integer representation of the key prefix.
pub type Version = u32;

/// HMAC with SHA-512
type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// Size of input key material and derived keys.
pub const KEY_SIZE: usize = 32;

#[cfg(test)]
mod test_mod{
    use super::*;
    
    pub(crate) struct TestVector{
        pub seed: &'static str,
        pub ckd: (&'static str, &'static str, &'static str)
    }

    const VECTORS :[TestVector;1] = [
        TestVector{
            seed: "000102030405060708090a0b0c0d0e0f",
            ckd: (
                "m",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
            )
        }
    ];

    #[test]
    pub fn test_vectors(){
        VECTORS.iter().for_each(|item|{
            let path : DerivationPath = item.ckd.0.parse().unwrap();
            let seed = hex::decode(item.seed).unwrap();
            let xprv = XPrv::new_from_path(seed,&path).unwrap();
            let xpub = xprv.public_key();
            assert_eq!(item.ckd.1,xprv.to_string(Prefix::XPRV).as_str());
            assert_eq!(item.ckd.2,xpub.to_string(Prefix::XPUB).as_str());
        })
    }
}