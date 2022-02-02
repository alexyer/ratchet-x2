#[cfg(feature = "std")]
use std::{collections::BTreeMap, marker::PhantomData};

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;

#[cfg(not(feature = "std"))]
use core::marker::PhantomData;

use cryptraits::{
    aead::Aead,
    convert::{Len, ToVec},
    hmac::Hmac,
    kdf::Kdf,
    key::{KeyPair, PublicKey, SecretKey},
    key_exchange::DiffieHellman,
};
use rand_core::{CryptoRng, RngCore};

use crate::errors::{DoubleRatchetError, DoubleRatchetResult};

pub type Secret = [u8; 32];

pub const MAX_SKIP: u32 = 2000;

pub struct DoubleRatchet<K, KDF, AEAD, HMAC>
where
    K: KeyPair + DiffieHellman,
    KDF: Kdf,
    AEAD: Aead,
    HMAC: Hmac,
    <K as DiffieHellman>::SSK: ToVec,
    <K as DiffieHellman>::PK: ToVec,
{
    /// DH Ratchet key pair (the "sending" or "self" ratchet key)
    dhs: K,

    /// DH Ratchet public key (the "received" or "remote" key)
    dhr: Option<K::PK>,

    /// 32-byte Root Key
    rk: Secret,

    /// 32-byte Chain Key for sending
    cks: Option<Secret>,

    /// 32-byte Chain Key for receiving
    ckr: Option<Secret>,

    /// Message number for sending
    ns: u32,

    /// Message number for receiving
    nr: u32,

    /// Number of messages in previous sending chain
    pn: u32,

    /// Dictionary of skipped-over message keys, indexed by ratchet public key and message number.
    mkskipped: BTreeMap<(Vec<u8>, u32), Secret>,

    _kdf: PhantomData<KDF>,
    _aead: PhantomData<AEAD>,
    _hmac: PhantomData<HMAC>,
}

#[derive(Debug, PartialEq)]
pub struct Header<PK: PublicKey> {
    dhs: PK,
    pn: u32,
    n: u32,
}

impl<PK: PublicKey + ToVec> ToVec for Header<PK> {
    fn to_vec(&self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut v = Vec::new();
        v.extend_from_slice(&self.dhs.to_vec());
        v.extend_from_slice(&self.pn.to_be_bytes());
        v.extend_from_slice(&self.n.to_be_bytes());
        v
    }
}

impl<PK: PublicKey + Len> Len for Header<PK> {
    const LEN: usize = PK::LEN + 8;
}

impl<K, KDF, AEAD, HMAC> DoubleRatchet<K, KDF, AEAD, HMAC>
where
    K: KeyPair + DiffieHellman,
    KDF: Kdf,
    AEAD: Aead,
    HMAC: Hmac,
    <K as DiffieHellman>::SSK: ToVec,
    <K as DiffieHellman>::PK: ToVec,
{
    /// Initialize "Alice": the sender of the first message.
    pub fn init_alice<R>(
        ssk: &impl ToVec,
        bob_dh_pk: K::PK,
        ckr: Option<Secret>,
        csprng: &mut R,
    ) -> DoubleRatchet<K, KDF, AEAD, HMAC>
    where
        R: CryptoRng + RngCore,
        K::SSK: ToVec,
    {
        let dhs = K::generate_with(csprng);
        let (rk, cks) = Self::kdf_rk(
            Some(&ssk.to_vec()),
            b"WhisperText",
            &dhs.diffie_hellman(&bob_dh_pk).to_vec(),
        )
        .unwrap();

        Self {
            dhs,
            dhr: Some(bob_dh_pk),
            rk,
            cks: Some(cks),
            ckr,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: BTreeMap::new(),
            _kdf: PhantomData::default(),
            _aead: PhantomData::default(),
            _hmac: PhantomData::default(),
        }
    }

    pub fn init_bob(rk: &impl ToVec, dhs: K, cks: Option<Secret>) -> Self {
        Self {
            dhs,
            dhr: None,
            rk: rk.to_vec().try_into().unwrap(),
            cks,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: BTreeMap::new(),
            _kdf: PhantomData::default(),
            _aead: PhantomData::default(),
            _hmac: PhantomData::default(),
        }
    }

    pub fn encrypt<R>(
        &mut self,
        data: &[u8],
        aad: &[u8],
        csprng: &mut R,
    ) -> (Header<<<K as KeyPair>::SK as SecretKey>::PK>, Vec<u8>)
    where
        R: CryptoRng + RngCore,
    {
        self.try_encrypt(data, aad, csprng).unwrap()
    }

    pub fn try_encrypt<R>(
        &mut self,
        data: &[u8],
        aad: &[u8],
        csprng: &mut R,
    ) -> DoubleRatchetResult<(Header<<<K as KeyPair>::SK as SecretKey>::PK>, Vec<u8>)>
    where
        R: CryptoRng + RngCore,
    {
        if let Some(dhr) = self.dhr {
            if self.cks.is_none() {
                self.dhs = K::generate_with(csprng);
                let (rk, cks) = Self::kdf_rk(
                    Some(&self.dhs.diffie_hellman(&dhr).to_vec()),
                    b"WhisperText",
                    &self.rk,
                )
                .unwrap();

                self.rk = rk;
                self.cks = Some(cks);
                self.pn = self.ns;
                self.ns = 0;
            }
        } else {
            return Err(DoubleRatchetError::NotInitialized);
        }

        let (new_cks, mk) = Self::kdf_ck(&self.cks.unwrap()).unwrap();
        self.cks = Some(new_cks);

        let header = self.header();

        let mut nonce = vec![0u8; 8];
        nonce.extend_from_slice(&self.ns.to_be_bytes());

        self.ns += 1;

        Ok((
            header,
            AEAD::new(&mk).encrypt(&nonce, data, Some(aad)).unwrap(),
        ))
    }

    fn kdf_rk(salt: Option<&[u8]>, info: &[u8], input: &[u8]) -> Result<(Secret, Secret), KDF::E> {
        let mut output = [0u8; 64];

        KDF::new(salt, input).expand(info, &mut output)?;

        let (root_key, chain_key) = output.split_at(32);

        Ok((root_key.try_into().unwrap(), chain_key.try_into().unwrap()))
    }

    fn kdf_ck(key: &[u8]) -> Result<(Secret, Secret), HMAC::E> {
        let mut mac = HMAC::new_from_slice(key)?;
        mac.update(&[0x01]);
        let ck = mac.finalize();

        let mut mac = HMAC::new_from_slice(key)?;
        mac.update(&[0x02]);
        let mk = mac.finalize();

        Ok((ck.try_into().unwrap(), mk.try_into().unwrap()))
    }

    fn header(&self) -> Header<<<K as KeyPair>::SK as SecretKey>::PK> {
        Header {
            dhs: self.dhs.to_public(),
            pn: self.pn,
            n: self.ns,
        }
    }

    pub fn decrypt<R>(
        &mut self,
        header: &Header<K::PK>,
        ciphertext: &[u8],
        aad: &[u8],
        csprng: &mut R,
    ) -> Vec<u8>
    where
        R: CryptoRng + RngCore,
    {
        self.try_decrypt(header, ciphertext, aad, csprng).unwrap()
    }

    pub fn try_decrypt<R>(
        &mut self,
        header: &Header<K::PK>,
        ciphertext: &[u8],
        aad: &[u8],
        csprng: &mut R,
    ) -> DoubleRatchetResult<Vec<u8>>
    where
        R: CryptoRng + RngCore,
    {
        let mut nonce = vec![0u8; 8];
        nonce.extend_from_slice(&header.n.to_be_bytes());

        if let Some(mk) = self.mkskipped.remove(&(header.dhs.to_vec(), header.n)) {
            return AEAD::new(&mk)
                .decrypt(&nonce, ciphertext, Some(aad))
                .or(Err(DoubleRatchetError::AeadError));
        }

        if Some(&header.dhs) != self.dhr.as_ref() {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header, csprng)
        }

        self.skip_message_keys(header.n)?;

        let (ckr, mk) = Self::kdf_ck(&self.ckr.unwrap()).unwrap();
        self.ckr = Some(ckr);
        self.nr += 1;

        AEAD::new(&mk)
            .decrypt(&nonce, ciphertext, Some(aad))
            .or(Err(DoubleRatchetError::AeadError))
    }

    fn dh_ratchet<R>(&mut self, header: &Header<K::PK>, csprng: &mut R)
    where
        R: CryptoRng + RngCore,
    {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dhs);

        let (rk, ckr) = Self::kdf_rk(
            Some(&self.rk),
            b"WhisperText",
            &self.dhs.diffie_hellman(&self.dhr.unwrap()).to_vec(),
        )
        .unwrap();

        self.rk = rk;
        self.ckr = Some(ckr);
        self.dhs = K::generate_with(csprng);

        let (rk, cks) = Self::kdf_rk(
            Some(&self.rk),
            b"WhisperText",
            &self.dhs.diffie_hellman(&self.dhr.unwrap()).to_vec(),
        )
        .unwrap();

        self.rk = rk;
        self.cks = Some(cks);
    }

    fn skip_message_keys(&mut self, until: u32) -> DoubleRatchetResult<()> {
        if self.nr + MAX_SKIP < until {
            return Err(DoubleRatchetError::TooManySkippedKeys);
        }

        if let Some(ckr) = self.ckr {
            while self.nr < until {
                let (ckr, mk) = Self::kdf_ck(&ckr).unwrap();
                self.ckr = Some(ckr);
                self.mkskipped
                    .insert((self.dhr.unwrap().to_vec(), self.nr), mk);
                self.nr += 1;
            }
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "cryptimitives"))]
mod tests {
    use cryptimitives::{aead, hmac, kdf, key::x25519_ristretto};
    use rand_core::OsRng;

    use super::*;

    type DR = DoubleRatchet<
        x25519_ristretto::KeyPair,
        kdf::sha256::Kdf,
        aead::aes_gcm::Aes256Gcm,
        hmac::sha256::Hmac,
    >;

    fn asymmetric_setup<R>(csprng: &mut R) -> (DR, DR)
    where
        R: CryptoRng + RngCore,
    {
        let alice_pair = x25519_ristretto::KeyPair::default();
        let bob_pair = x25519_ristretto::KeyPair::default();

        let ssk = alice_pair.diffie_hellman(bob_pair.public());

        let alice = DR::init_alice(&ssk, bob_pair.to_public(), None, csprng);
        let bob = DR::init_bob(&ssk, bob_pair, None);

        (alice, bob)
    }

    #[test]
    fn test_asymmetric() {
        let (mut alice, mut bob) = asymmetric_setup(&mut OsRng);

        let (pt_a, ad_a) = (b"Hey, Bob", b"A2B");
        let (pt_b, ad_b) = (b"Hey, Alice", b"B2A");

        let (header_a, ciphertext_a) = alice.encrypt(pt_a, ad_a, &mut OsRng);

        assert_eq!(
            bob.try_encrypt(pt_b, ad_b, &mut OsRng),
            Err(DoubleRatchetError::NotInitialized)
        );

        assert_eq!(
            bob.decrypt(&header_a, &ciphertext_a, ad_a, &mut OsRng),
            Vec::from(&pt_a[..])
        );
    }

    #[test]
    fn test_out_of_order() {
        let (mut alice, mut bob) = asymmetric_setup(&mut OsRng);

        let (ad_a, ad_b) = (b"A2B", b"B2A");
        let pt_a_0 = b"Good day Robert";

        let (h_a_0, ct_a_0) = alice.encrypt(pt_a_0, ad_a, &mut OsRng);

        assert_eq!(
            bob.decrypt(&h_a_0, &ct_a_0, ad_a, &mut OsRng),
            Vec::from(&pt_a_0[..])
        );

        let pt_a_1 = b"Do you like Rust?";
        let (h_a_1, ct_a_1) = alice.encrypt(pt_a_1, ad_a, &mut OsRng);

        // Bob misses pt_a_1

        let pt_b_0 = b"Salutations Allison";
        let (h_b_0, ct_b_0) = bob.encrypt(pt_b_0, ad_b, &mut OsRng);

        // Alice misses pt_b_0
        let pt_b_1 = b"How is your day going?";
        let (h_b_1, ct_b_1) = bob.encrypt(pt_b_1, ad_b, &mut OsRng);

        assert_eq!(
            alice.decrypt(&h_b_1, &ct_b_1, ad_b, &mut OsRng),
            Vec::from(&pt_b_1[..])
        );

        let pt_a_2 = b"My day is fine.";
        let (h_a_2, ct_a_2) = alice.encrypt(pt_a_2, ad_a, &mut OsRng);

        assert_eq!(
            bob.decrypt(&h_a_2, &ct_a_2, ad_a, &mut OsRng),
            Vec::from(&pt_a_2[..])
        );

        // now Bob receives pt_a_1
        assert_eq!(
            bob.decrypt(&h_a_1, &ct_a_1, ad_a, &mut OsRng),
            Vec::from(&pt_a_1[..])
        );

        let pt_b_2 = b"Yes, I like Rust";
        let (h_b_2, ct_b_2) = bob.encrypt(pt_b_2, ad_b, &mut OsRng);

        assert_eq!(
            alice.decrypt(&h_b_2, &ct_b_2, ad_b, &mut OsRng),
            Vec::from(&pt_b_2[..])
        );

        // now Alice receives pt_b_0
        assert_eq!(
            alice.decrypt(&h_b_0, &ct_b_0, ad_b, &mut OsRng),
            Vec::from(&pt_b_0[..])
        );
    }
}
