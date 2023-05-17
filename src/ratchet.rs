use std::collections::VecDeque;
#[cfg(feature = "std")]
use std::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use cryptimitives::key::x25519_ristretto;

#[cfg(not(feature = "std"))]
use core::marker::PhantomData;

#[cfg(feature = "serde_derive")]
use serde::{Deserialize, Serialize};

use cryptraits::{
    aead::Aead,
    convert::{Len, ToVec},
    hmac::Hmac,
    kdf::Kdf,
    key::{Generate, KeyPair, PublicKey, SecretKey},
    key_exchange::DiffieHellman,
};
use rand_core::{CryptoRng, RngCore};

use crate::errors::{DoubleRatchetError, DoubleRatchetResult};

pub type Secret = [u8; 32];

pub const DEFAULT_MAX_SKIP: usize = 2000;

pub struct DoubleRatchetOptions {
    pub max_skip: usize,
}

impl Default for DoubleRatchetOptions {
    fn default() -> Self {
        Self {
            max_skip: DEFAULT_MAX_SKIP,
        }
    }
}

#[cfg(not(feature = "serde_derive"))]
trait DrPkToVec: ToVec {}

#[cfg(feature = "serde_derive")]
pub trait DrPkToVec: ToVec + Serialize + for<'a> Deserialize<'a> {}

#[cfg(feature = "serde_derive")]
impl DrPkToVec for x25519_ristretto::PublicKey {}

#[cfg(not(feature = "serde_derive"))]
pub struct DoubleRatchet<K, KDF, AEAD, HMAC>
where
    K: KeyPair + DiffieHellman,
    KDF: Kdf,
    AEAD: Aead,
    HMAC: Hmac,
    <K as DiffieHellman>::SSK: ToVec,
    <K as DiffieHellman>::PK: DrPkToVec,
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
    mkskipped: VecDeque<(Vec<u8>, u32, Secret)>,

    /// Max number of skipped-over message keys in storage.
    max_skipped: usize,

    _kdf: PhantomData<KDF>,
    _aead: PhantomData<AEAD>,
    _hmac: PhantomData<HMAC>,
}

#[cfg(feature = "serde_derive")]
#[derive(Serialize, Deserialize)]
pub struct DoubleRatchet<K, KDF, AEAD, HMAC>
where
    K: KeyPair + DiffieHellman,
    KDF: Kdf,
    AEAD: Aead,
    HMAC: Hmac,
    <K as DiffieHellman>::SSK: ToVec,
    <K as DiffieHellman>::PK: DrPkToVec,
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
    mkskipped: VecDeque<(Vec<u8>, u32, Secret)>,

    /// Max number of skipped-over message keys in storage.
    max_skipped: usize,

    #[serde(skip_serializing, skip_deserializing)]
    _kdf: PhantomData<KDF>,

    #[serde(skip_serializing, skip_deserializing)]
    _aead: PhantomData<AEAD>,

    #[serde(skip_serializing, skip_deserializing)]
    _hmac: PhantomData<HMAC>,
}

/// Double Ratchet message header.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde_derive", derive(Serialize, Deserialize))]
pub struct Header<PK: PublicKey> {
    /// DH Ratchet key (the "sending" or "self" ratchet key)
    dhs: PK,

    /// Number of messages in previous sending chain
    pn: u32,

    /// Message number
    n: u32,
}

impl<PK: PublicKey> Header<PK> {
    pub fn dhs(&self) -> &PK {
        &self.dhs
    }

    pub fn pn(&self) -> u32 {
        self.pn
    }

    pub fn n(&self) -> u32 {
        self.n
    }
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

impl<'a, K, KDF, AEAD, HMAC> DoubleRatchet<K, KDF, AEAD, HMAC>
where
    K: KeyPair + DiffieHellman + Generate,
    KDF: Kdf,
    AEAD: Aead,
    HMAC: Hmac,
    <K as DiffieHellman>::SSK: ToVec,
    <K as DiffieHellman>::PK: DrPkToVec,
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
        Self::do_init_alice(
            ssk,
            bob_dh_pk,
            ckr,
            &DoubleRatchetOptions::default(),
            csprng,
        )
    }

    /// Initialize "Alice": the sender of the first message, with custom options.
    pub fn init_alice_with_options<R>(
        ssk: &impl ToVec,
        bob_dh_pk: K::PK,
        ckr: Option<Secret>,
        opts: &DoubleRatchetOptions,
        csprng: &mut R,
    ) -> DoubleRatchet<K, KDF, AEAD, HMAC>
    where
        R: CryptoRng + RngCore,
        K::SSK: ToVec,
    {
        Self::do_init_alice(ssk, bob_dh_pk, ckr, opts, csprng)
    }

    pub fn do_init_alice<R>(
        ssk: &impl ToVec,
        bob_dh_pk: K::PK,
        ckr: Option<Secret>,
        opts: &DoubleRatchetOptions,
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
            mkskipped: Default::default(),
            max_skipped: opts.max_skip,
            _kdf: PhantomData::default(),
            _aead: PhantomData::default(),
            _hmac: PhantomData::default(),
        }
    }

    /// Initialize "Bob": the receiver of the first message.
    pub fn init_bob(rk: &impl ToVec, dhs: K, cks: Option<Secret>) -> Self {
        Self::do_init_bob(rk, dhs, cks, &DoubleRatchetOptions::default())
    }

    /// Initialize "Bob": the receiver of the first message, with custom options.
    pub fn init_bob_with_options(
        rk: &impl ToVec,
        dhs: K,
        cks: Option<Secret>,
        opts: &DoubleRatchetOptions,
    ) -> Self {
        Self::do_init_bob(rk, dhs, cks, opts)
    }

    pub fn do_init_bob(
        rk: &impl ToVec,
        dhs: K,
        cks: Option<Secret>,
        opts: &DoubleRatchetOptions,
    ) -> Self {
        Self {
            dhs,
            dhr: None,
            rk: rk.to_vec().try_into().unwrap(),
            cks,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: Default::default(),
            max_skipped: opts.max_skip,
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

        if let Some(mk) = self.get_skipped_message_key(header.dhs, header.n) {
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
        while self.nr < until {
            if self.mkskipped.len() >= self.max_skipped {
                self.mkskipped.pop_front();
            }

            if let Some(ckr) = self.ckr {
                let (ckr, mk) = Self::kdf_ck(&ckr).unwrap();
                self.ckr = Some(ckr);
                self.mkskipped
                    .push_back((self.dhr.unwrap().to_vec(), self.nr, mk));
                self.nr += 1;
            }
        }
        Ok(())
    }

    fn get_skipped_message_key(&mut self, ratchet_key: impl ToVec, n: u32) -> Option<[u8; 32]> {
        let pk = ratchet_key.to_vec();

        self.mkskipped
            .iter()
            .position(|(skipped_pk, skipped_n, _)| skipped_pk == &pk && *skipped_n == n)
            .and_then(|index| self.mkskipped.remove(index))
            .map(|(_, _, mk)| mk)
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

    fn asymmetric_setup<R>(opts: Option<DoubleRatchetOptions>, csprng: &mut R) -> (DR, DR)
    where
        R: CryptoRng + RngCore,
    {
        let alice_pair = x25519_ristretto::KeyPair::default();
        let bob_pair = x25519_ristretto::KeyPair::default();

        let ssk = alice_pair.diffie_hellman(bob_pair.public());

        let opts = opts.unwrap_or_default();

        let alice = DR::init_alice_with_options(&ssk, bob_pair.to_public(), None, &opts, csprng);
        let bob = DR::init_bob_with_options(&ssk, bob_pair, None, &opts);

        (alice, bob)
    }

    #[test]
    fn test_asymmetric() {
        let (mut alice, mut bob) = asymmetric_setup(None, &mut OsRng);

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
        let (mut alice, mut bob) = asymmetric_setup(None, &mut OsRng);

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

        let pt_a_3 = b"My day is not that fine...";
        let (h_a_3, ct_a_3) = alice.encrypt(pt_a_3, ad_a, &mut OsRng);

        let pt_a_4 = b"Its rainy";
        let (h_a_4, ct_a_4) = alice.encrypt(pt_a_4, ad_a, &mut OsRng);

        let pt_a_5 = b"And windy";
        let (h_a_5, ct_a_5) = alice.encrypt(pt_a_5, ad_a, &mut OsRng);

        let pt_a_6 = b"And muddy";
        let (h_a_6, ct_a_6) = alice.encrypt(pt_a_6, ad_a, &mut OsRng);

        assert_eq!(
            bob.decrypt(&h_a_6, &ct_a_6, ad_a, &mut OsRng),
            Vec::from(&pt_a_6[..])
        );

        assert_eq!(
            bob.decrypt(&h_a_5, &ct_a_5, ad_a, &mut OsRng),
            Vec::from(&pt_a_5[..])
        );

        assert_eq!(
            bob.decrypt(&h_a_4, &ct_a_4, ad_a, &mut OsRng),
            Vec::from(&pt_a_4[..])
        );

        assert_eq!(
            bob.decrypt(&h_a_2, &ct_a_2, ad_a, &mut OsRng),
            Vec::from(&pt_a_2[..])
        );

        assert_eq!(
            bob.decrypt(&h_a_3, &ct_a_3, ad_a, &mut OsRng),
            Vec::from(&pt_a_3[..])
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

    #[cfg(feature = "serde_derive")]
    #[test]
    fn test_asymmetric_serde() {
        let (bob_serialized, header_a, ciphertext_a, ad_a, pt_a) = {
            let (mut alice, mut bob) = asymmetric_setup(None, &mut OsRng);

            let (pt_a, ad_a) = (b"Hey, Bob", b"A2B");
            let (pt_b, ad_b) = (b"Hey, Alice", b"B2A");

            let (header_a, ciphertext_a) = alice.encrypt(pt_a, ad_a, &mut OsRng);

            assert_eq!(
                bob.try_encrypt(pt_b, ad_b, &mut OsRng),
                Err(DoubleRatchetError::NotInitialized)
            );

            (
                serde_json::to_string(&bob).unwrap(),
                header_a,
                ciphertext_a,
                ad_a,
                pt_a,
            )
        };

        let mut bob: DR = serde_json::from_str(&bob_serialized).unwrap();

        assert_eq!(
            bob.decrypt(&header_a, &ciphertext_a, ad_a, &mut OsRng),
            Vec::from(&pt_a[..])
        );
    }

    #[cfg(feature = "serde_derive")]
    #[test]
    fn test_out_of_order_serde() {
        let (mut alice, mut bob) = asymmetric_setup(None, &mut OsRng);

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

        let bob_serialized = serde_json::to_string(&bob).unwrap();

        let mut bob: DR = serde_json::from_str(&bob_serialized).unwrap();

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

    #[test]
    fn test_max_keys() {
        let (mut alice, mut bob) =
            asymmetric_setup(Some(DoubleRatchetOptions { max_skip: 5 }), &mut OsRng);

        let (pt_a, ad_a) = (b"Hey, Bob", b"A2B");

        let (mut header_a, mut ciphertext_a) = alice.encrypt(pt_a, ad_a, &mut OsRng);

        for _ in 0..=DEFAULT_MAX_SKIP {
            (header_a, ciphertext_a) = alice.encrypt(pt_a, ad_a, &mut OsRng);
        }

        assert_eq!(
            bob.decrypt(&header_a, &ciphertext_a, ad_a, &mut OsRng),
            Vec::from(&pt_a[..])
        );
    }
}
