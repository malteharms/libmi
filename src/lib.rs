mod crypto;

use jni::{
    objects::{JByteArray, JClass, JString},
    JNIEnv,
};

use crate::crypto::{aes, hash};

#[no_mangle]
pub extern "system" fn Java_de_malteharms_libmi_Native_encrypt<'local>(
    env: JNIEnv<'local>,
    _: JClass<'local>,
    jptext: JByteArray<'local>,
    jkey: JByteArray<'local>
) -> JByteArray<'local> {
    let plain_text = env.convert_byte_array(&jptext).unwrap();
    let key = env.convert_byte_array(&jkey).unwrap();

    if key.len() != 32 {
        let error_buffer: [u8; 1] = [0];
        return env.byte_array_from_slice(&error_buffer).unwrap();
    }

    let iv: [u8; 16] = [1;16];

    let cipher: Vec<u8> = 
        aes::aes_256_cbc_encrypt(&plain_text, &key, &iv).unwrap();
    
    let output = env.byte_array_from_slice(&cipher).unwrap();
    
    output
}

#[no_mangle]
pub extern "system" fn Java_de_malteharms_libmi_Native_decrypt<'local>(
    env: JNIEnv<'local>,
    _: JClass<'local>,
    jctext: JByteArray<'local>,
    jkey: JByteArray<'local>
) -> JByteArray<'local> {
    let ctext = env.convert_byte_array(&jctext).unwrap();
    let key = env.convert_byte_array(&jkey).unwrap();
    
    let iv: [u8; 16] = [1;16];

    let ptext: Vec<u8> = 
        aes::aes_256_cbc_decrypt(&ctext, &key, &iv).unwrap();

    let output = env.byte_array_from_slice(&ptext).unwrap();
    
    output
}

#[no_mangle]
pub extern "system" fn Java_de_malteharms_libmi_Native_sha256<'local>(
    mut env: JNIEnv<'local>,
    _: JClass<'local>,
    input: JString<'local>,
) -> JString<'local> {
    let string_to_hash: String = 
        env.get_string(&input).expect("Could not convert string").into();
    
    let hash: String = hash::perform_hash(&string_to_hash);
    
    let output = env.new_string(hash)
        .expect("Couldn't create java string!");

    // Finally, extract the raw pointer to return.
    output
}

#[no_mangle]
pub extern "system" fn Java_de_malteharms_libmi_Native_generateKeyPair<'local>(
    env: JNIEnv<'local>,
    _: JClass<'local>,
) -> JByteArray<'local> {
    
    // ... (perform keypair generation)
    
    let buf = [1; 2000];
    let output = env.byte_array_from_slice(&buf).unwrap();
    
    output
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_de_malteharms_libmi_Native_calculateECDHE<'local>(
    env: JNIEnv<'local>,
    _: JClass<'local>,
    ourPrivateKey: JByteArray<'local>,
    theirPublicKey: JByteArray<'local>
) -> JByteArray<'local> {
    let _opk = env.convert_byte_array(&ourPrivateKey).unwrap();
    let _tpk = env.convert_byte_array(&theirPublicKey).unwrap();
    
    // ... (perform decryption)
    
    let buf = [1; 2000];
    let output = env.byte_array_from_slice(&buf).unwrap();
    
    output
}



#[cfg(test)]
mod procedure_tests {
    use crate::crypto::aes;

    #[test]
    fn encrypt_and_decrypt_procedure_test() {
        let key: [u8; 32] = [1; 32];
        let iv: [u8; 16] = [1; 16];

        let dummy_ptext: [u8; 40] = [2; 40];

        let cipher: Vec<u8> = 
            aes::aes_256_cbc_encrypt(&dummy_ptext, &key, &iv).unwrap();
        let ptext: Vec<u8> = 
            aes::aes_256_cbc_decrypt(&cipher, &key, &iv).unwrap();
        
        assert_eq!(
            ptext,
            dummy_ptext
        );
    }
}