# RATCHET-X2
Pure Rust Double Ratchet protocol implementation

## Example
```rust
use cryptimitives::{aead, hmac, kdf, key::x25519_ristretto};
use cryptraits::{key::KeyPair, key_exchange::DiffieHellman};
use rand_core::OsRng;
use ratchet_x2::DoubleRatchet;

type DR = DoubleRatchet<
    x25519_ristretto::KeyPair,
    kdf::sha256::Kdf,
    aead::aes_gcm::Aes256Gcm,
    hmac::sha256::Hmac,
>;

fn main() {
    let alice_pair = x25519_ristretto::KeyPair::default();
    let bob_pair = x25519_ristretto::KeyPair::default();

    let ssk = alice_pair.diffie_hellman(bob_pair.public());

    let mut alice = DR::init_alice(&ssk, bob_pair.to_public(), None, &mut OsRng);
    let mut bob = DR::init_bob(&ssk, bob_pair, None);

    let (pt_a, ad_a) = (b"Hey, Bob", b"A2B");

    let (header_a, ciphertext_a) = alice.encrypt(pt_a, ad_a, &mut OsRng);

    let decrypted_msg = bob.decrypt(&header_a, &ciphertext_a, ad_a, &mut OsRng);

    println!("{}", String::from_utf8(decrypted_msg).unwrap());
}
```