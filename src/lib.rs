#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod bip39;
pub mod bip32;

#[cfg(test)]
mod tests {
    use crate::bip39::{Mnemonic, Language, MnemonicType, Seed};
    use crate::bip32::{XPrv,XPub,DerivationPath, Prefix, ChildNumber};
    
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
        let xprv = XPrv::derive_from_path(seed,&path).unwrap();
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
}
