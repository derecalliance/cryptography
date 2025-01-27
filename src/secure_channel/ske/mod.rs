/*
 * Copyright (c) DeRec Alliance and its Contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use aead::Result;
use aes_gcm::{aead::Aead, Aes256Gcm, Nonce, Key};
use aes::cipher::{
    typenum::*,
    KeyInit,
};

pub const DEREC_CHANNEL_KEY_LENGTH: usize = 32;

pub fn encrypt_message(msg: &[u8], key: &[u8; DEREC_CHANNEL_KEY_LENGTH]) -> Vec<u8> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::<U12>::default();

    cipher.encrypt(&nonce, msg).unwrap()
}

pub fn decrypt_message(ctxt: &[u8], key: &[u8; DEREC_CHANNEL_KEY_LENGTH]) -> Result<Vec<u8>> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::<U12>::default();

    cipher.decrypt(&nonce, ctxt)
}
