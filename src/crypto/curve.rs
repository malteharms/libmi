use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

const AGREEMENT_LENGTH: usize = 32;
pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;


pub fn generate_key_pair() -> [u8; 64] {
    
    let private_key: PrivateKey = PrivateKey::new();

    let private_key_bytes: [u8; PRIVATE_KEY_LENGTH] = private_key.private_key_bytes(); 
    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = private_key.derive_public_key_bytes();

    let return_value: [u8; 64] = merge_arrays(private_key_bytes, public_key_bytes);
    return_value
}

pub fn calculate_agreement(
    our_private_key_vector: Vec<u8>, 
    their_public_key_vector: Vec<u8>
) -> [u8; AGREEMENT_LENGTH] {
    
    let our_private_key_bytes: [u8; 32] = convert(our_private_key_vector);
    let their_public_key_bytes: [u8; 32] = convert(their_public_key_vector);

    let private_key: PrivateKey = PrivateKey::from(our_private_key_bytes);
    let sk: [u8; 32] = private_key.calculate_agreement(&their_public_key_bytes);

    sk
}

pub struct PrivateKey {
    secret: StaticSecret,
}

impl PrivateKey {
    pub fn new() -> Self {
        let mut csprng = rand::rngs::OsRng;
        
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        bytes = clamp_integer(bytes);

        let secret = StaticSecret::from(bytes);
        PrivateKey { secret }
    }

    pub fn calculate_agreement(
        &self,
        their_public_key: &[u8; PUBLIC_KEY_LENGTH],
    ) -> [u8; AGREEMENT_LENGTH] {
        *self
            .secret
            .diffie_hellman(&PublicKey::from(*their_public_key))
            .as_bytes()
    }

    pub fn derive_public_key_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        *PublicKey::from(&self.secret).as_bytes()
    }

    pub fn private_key_bytes(&self) -> [u8; PRIVATE_KEY_LENGTH] {
        self.secret.to_bytes()
    }
}

impl From<[u8; PRIVATE_KEY_LENGTH]> for PrivateKey {
    fn from(private_key: [u8; 32]) -> Self {
        let secret: StaticSecret = StaticSecret::from(clamp_integer(private_key));
        PrivateKey { secret }
    }
}

fn clamp_integer(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 0b1111_1000;
    bytes[31] &= 0b0111_1111;
    bytes[31] |= 0b0100_0000;
    bytes
}

fn merge_arrays(arr1: [u8; 32], arr2: [u8; 32]) -> [u8; 64] {
    let mut result = [0u8; 64];
    for i in 0..32 {
        result[i] = arr1[i];
        result[i + 32] = arr2[i];
    }
    result
}

fn convert(vec: Vec<u8>) -> [u8; 32] {
    assert_eq!(vec.len(), 32);
    
    let mut arr = [0u8; 32];
    arr[..vec.len()].copy_from_slice(&vec);
    arr
}