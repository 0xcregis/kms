#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod bip39;
pub mod bip32;
pub mod error;
pub mod crypto;

use error::Error;

pub fn ecdsa_sign(secret: &libsecp256k1::SecretKey, bytes: &[u8]) -> Result<([u8;64],u8), Error> {
    let message = libsecp256k1::Message::parse_slice(bytes)?;
    let (signature, recid) = libsecp256k1::sign(&message, secret);
    let signature = signature.serialize();
    Ok((signature,recid.into()))
}


#[cfg(test)]
mod tests {
    use crate::bip39::{Mnemonic, Language, MnemonicType, Seed};
    use crate::bip32::{XPrv, XPub, DerivationPath, Prefix, ChildNumber};
    use super::ecdsa_sign;

    #[test]
    fn test_mnemonic() {
        let phrase = "heavy face learn track claw jaguar pigeon uncle seven enough glow where";
        // let mnemonic =  Mnemonic::new(MnemonicType::Words12,Language::English);
        let mnemonic = Mnemonic::from_phrase(phrase,Language::English).unwrap();
        //let phrase = mnemonic.phrase();
        assert_eq!(phrase,mnemonic.phrase());
        println!("phrase:{:#?}",phrase);
        let seed = Seed::new(&mnemonic, "");
        println!("seed:{:X}",seed);
        
        let path: DerivationPath = "m/44'/196'/300049'/0".parse().unwrap();
        let xprv = XPrv::new_from_path(seed,&path).unwrap();
        let ek = xprv.to_extended_key(Prefix::XPRV);
        println!("xprv:{:?}",xprv);
        let cp: ChildNumber = 1u32.into();
        let cx = xprv.derive_child(cp).unwrap();
        let mut hex = String::new();
        for b in cx.to_bytes(){
            hex.push_str(format!("{:X}",b).as_str());
        }
        println!("{}",hex)
    }

    #[test]
    fn test_master_xprv() {
        let phrase = "heavy face learn track claw jaguar pigeon uncle seven enough glow where";
        // let mnemonic =  Mnemonic::new(MnemonicType::Words12,Language::English);
        let mnemonic = Mnemonic::from_phrase(phrase,Language::English).unwrap();
        //let phrase = mnemonic.phrase();
        let seed = Seed::new(&mnemonic, "");
        // let path: DerivationPath = "m".parse().unwrap();
        let xprv = XPrv::new(seed).unwrap();
        let secret = xprv.private_key();
        //let ek = xprv.to_extended_key(Prefix::XPRV);
        println!("xprv:{:}",xprv.to_string(Prefix::XPRV).as_str());
    }
    

    #[test]
    fn test_xpub(){
        let phrase = "deal pretty baby midnight federal capital suggest cheese creek mutual boil shine";
        let mnemonic = Mnemonic::from_phrase(phrase,Language::English).unwrap();
        //let phrase = mnemonic.phrase();
        let seed = Seed::new(&mnemonic, "");
        let path: DerivationPath = "m/44'/60".parse().unwrap();
        let xprv = XPrv::new_from_path(seed,&path).unwrap();
        let xpub: XPub = xprv.public_key();
        
        println!("{}",xpub.to_string(Prefix::XPUB));
        // xpub6BpaER2tMZzYkPttmAhbbtd6MRyKtPTaPrEbyXHwkjM7G9ySmv81pGqaVBXF3A1UfbL7VpMhdigyZ1Fz17nQNwFJqkzEye6xKcsiPj2uTDZ
    }

}
