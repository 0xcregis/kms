//! Trait for deriving child keys on a given type.

use crate::bip32::{KeyFingerprint, PrivateKeyBytes, Result, KEY_SIZE};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::bip32::XPub;


use crate::bip32::Error;

/// Bytes which represent a public key.
///
/// Includes an extra byte for an SEC1 tag.
pub type PublicKeyBytes = [u8; KEY_SIZE + 1];

/// Trait for key types which can be derived using BIP32.
pub trait PublicKey: Sized {
    /// Initialize this key from bytes.
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self>;

    /// Serialize this key as bytes.
    fn to_bytes(&self) -> PublicKeyBytes;

    /// Derive a child key from a parent key and a provided tweak value.
    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self>;

    /// Compute a 4-byte key fingerprint for this public key.
    ///
    /// Default implementation uses `RIPEMD160(SHA256(public_key))`.
    fn fingerprint(&self) -> KeyFingerprint {
        let digest = Ripemd160::digest(&Sha256::digest(&self.to_bytes()));
        digest[..4].try_into().expect("digest truncated")
    }
}

/* 
impl PublicKey for k256::PublicKey {
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        Ok(k256::PublicKey::from_sec1_bytes(&bytes)?)
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        self.to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("malformed public key")
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        let child_scalar =
            Option::<k256::NonZeroScalar>::from(k256::NonZeroScalar::from_repr(other.into()))
                .ok_or(Error::Crypto)?;

        let child_point = self.to_projective() + (k256::AffinePoint::generator() * *child_scalar);
        Self::from_affine(child_point.into()).map_err(|_| Error::Crypto)
    }
}


impl PublicKey for k256::ecdsa::VerifyingKey {
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        Ok(k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)?)
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        self.to_bytes()
            .as_slice()
            .try_into()
            .expect("malformed key")
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        k256::PublicKey::from(self)
            .derive_child(other)
            .map(Into::into)
    }
}
*/

impl PublicKey for libsecp256k1::PublicKey{
    fn from_bytes(bytes: PublicKeyBytes) -> Result<Self> {
        match libsecp256k1::PublicKey::parse_compressed(&bytes){
            Ok(pubkey) => Ok(pubkey),
            Err(_) => Err(Error::Crypto)
        }
    }

    fn to_bytes(&self) -> PublicKeyBytes {
        libsecp256k1::PublicKey::serialize_compressed(&self)
    }

    fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self> {
        let mut cpk = self.clone();
        match cpk.tweak_add_assign(&libsecp256k1::SecretKey::parse(&other).unwrap()){
            Ok(_) => Ok(cpk),
            Err(_) => Err(Error::Crypto)
        }
    }
}

impl From<XPub> for libsecp256k1::PublicKey {
    fn from(xpub: XPub) -> libsecp256k1::PublicKey {
        libsecp256k1::PublicKey::from(&xpub)
    }
}


impl From<&XPub> for libsecp256k1::PublicKey {
    fn from(xpub: &XPub) ->libsecp256k1::PublicKey {
        *xpub.public_key()
    }
}

/*
impl From<XPub> for k256::ecdsa::VerifyingKey {
    fn from(xpub: XPub) -> k256::ecdsa::VerifyingKey {
        k256::ecdsa::VerifyingKey::from(&xpub)
    }
}


impl From<&XPub> for k256::ecdsa::VerifyingKey {
    fn from(xpub: &XPub) -> k256::ecdsa::VerifyingKey {
        *xpub.public_key()
    }
}

 */



#[cfg(test)]
mod tests {
    use hex_literal::hex;

    const SEED: [u8; 64] = hex!(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2
         9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    );

    type XPrv = crate::bip32::ExtendedPrivateKey<libsecp256k1::SecretKey>;

    #[test]
    fn secp256k1_xprv_derivation() {
        let path = "m/0/2147483647'/1/2147483646'/2";
        let xprv = XPrv::derive_from_path(&SEED, &path.parse().unwrap()).unwrap();

        assert_eq!(
            xprv.public_key(),
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt".parse().unwrap()
        );
    }

    #[test]
    fn secp256k1_ffi_xpub_derivation() {
        let path = "m/0/2147483647'/1/2147483646'";
        let xprv = XPrv::derive_from_path(&SEED, &path.parse().unwrap()).unwrap();
        let xpub = xprv.public_key().derive_child(2.into()).unwrap();

        assert_eq!(
            xpub,
            "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt".parse().unwrap()
        );
    }
}