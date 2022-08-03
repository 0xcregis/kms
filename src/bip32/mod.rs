mod error;
mod prefix;
mod child_number;
mod private_key;
mod public_key;
mod extended_key;
mod derivation_path;
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