//! Streaming mode.

use alloc::string::ToString;

use crate::artifacts::{PublicKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use crate::client::*;
use crate::error::Error;
use crate::identity::{EncryptionPolicy, Policy};
use ibe::kem::cgw_kv::CGWKV;
use ibs::gg::{Identity, Signature, Signer, Verifier, SIG_BYTES};

use reck::Deck;
use alloc::vec::Vec;
use futures::io::{AsyncRead, AsyncWrite};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::TryFutureExt;
use rand::{CryptoRng, RngCore};

/// Configures an [`Sealer`] to process a payload stream.
#[derive(Debug)]
pub struct SealerStreamConfig {
    /// Segment size.
    segment_size: u32,
    /// AEAD key.
    key: [u8; KEY_SIZE],
    /// AEAD nonce.
    nonce: [u8; STREAM_NONCE_SIZE],
}

/// Configures an [`Unsealer`] to process a payload stream.
#[derive(Debug)]
pub struct UnsealerStreamConfig {
    segment_size: u32,
}

impl SealerConfig for SealerStreamConfig {}
impl UnsealerConfig for UnsealerStreamConfig {}
impl crate::client::sealed::SealerConfig for SealerStreamConfig {}
impl crate::client::sealed::UnsealerConfig for UnsealerStreamConfig {}

impl<'r, Rng: RngCore + CryptoRng> Sealer<'r, Rng, SealerStreamConfig> {
    /// Construct a new [`Sealer`] that can process streaming payloads.
    pub fn new(
        pk: &PublicKey<CGWKV>,
        policies: &EncryptionPolicy,
        pub_sign_key: &SigningKeyExt,
        rng: &'r mut Rng,
    ) -> Result<Self, Error> {
        let (header, ss) = Header::new(pk, policies, rng)?;

        let (segment_size, _) = stream_mode_checked(&header)?;
        let Algorithm::Aes128Gcm(iv) = header.algo;

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; STREAM_NONCE_SIZE];

        key.copy_from_slice(&ss.0[..KEY_SIZE]);
        nonce.copy_from_slice(&iv.0[..STREAM_NONCE_SIZE]);

        Ok(Sealer {
            rng,
            header,
            pub_sign_key: pub_sign_key.clone(),
            priv_sign_key: None,
            config: SealerStreamConfig {
                segment_size,
                key,
                nonce,
            },
        })
    }

    /// Optional: Add a size hint.
    ///
    /// This can help the receiver save some reallocations.
    pub fn with_size_hint(mut self, size_hint: (u64, Option<u64>)) -> Self {
        self.header.mode = Mode::Streaming {
            segment_size: self.config.segment_size,
            size_hint,
        };

        self
    }

    /// Seals payload data from an [`AsyncRead`] into an [`AsyncWrite`].
    pub async fn seal<R, W>(self, mut r: R, mut w: W) -> Result<(), Error>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        w.write_all(&PRELUDE).await?;
        w.write_all(&VERSION_V3.to_be_bytes()).await?;

        let header_vec = bincode::serialize(&self.header)?;
        w.write_all(&u32::try_from(header_vec.len())?.to_be_bytes())
            .await?;
        w.write_all(&header_vec).await?;

        let mut signer = Signer::default().chain(&header_vec);
        let header_sig = signer.clone().sign(&self.pub_sign_key.key.0, self.rng);
        let header_sig_ext = SignatureExt {
            sig: header_sig,
            pol: self.pub_sign_key.policy.clone(),
        };
        let header_sig_bytes = bincode::serialize(&header_sig_ext)?;

        w.write_all(&u32::try_from(header_sig_bytes.len())?.to_be_bytes())
            .await?;
        w.write_all(&header_sig_bytes).await?;

        //let aead = Aes128Gcm::new_from_slice(&self.config.key)?;
        //let mut enc = EncryptorBE32::from_aead(aead, &self.config.nonce.into());
        let mut enc = Deck::new(&self.config.key, &self.config.nonce);

        // Check for a private signing key, otherwise fall back to the public one.
        let signing_key = self.priv_sign_key.unwrap_or(self.pub_sign_key);

        let pol_bytes = bincode::serialize(&signing_key.policy)?;
        let pol_len = pol_bytes.len();

        if pol_len + POL_SIZE_SIZE > self.config.segment_size as usize {
            return Err(Error::ConstraintViolation);
        }

        let mut buf = vec![0; self.config.segment_size as usize + TAG_SIZE];

        buf[..POL_SIZE_SIZE].copy_from_slice(&u32::try_from(pol_len)?.to_be_bytes());
        buf[POL_SIZE_SIZE..POL_SIZE_SIZE + pol_len].copy_from_slice(&pol_bytes);

        let mut buf_tail = POL_SIZE_SIZE + pol_len;
        let mut start = buf_tail;

        // First segment: DEM.K (pol_len || pol || m_0 || sig_0 )
        // Other segments: DEM.K (m_i || sig_0)

        let mut counter: u32 = 0;

        loop {
            let read = r
                .read(&mut buf[buf_tail..self.config.segment_size as usize])
                .await?;
            buf_tail += read;

            if buf_tail == self.config.segment_size as usize {
                buf.truncate(buf_tail);

                signer.update(&buf[start..]);
                let sig = signer
                    .clone()
                    .chain(&counter.to_be_bytes())
                    .chain(&[0x00])
                    .sign(&signing_key.key.0, self.rng);
                bincode::serialize_into(&mut buf, &sig)?;

                enc.wrap(&mut buf).unwrap();

                w.write_all(&buf).await?;

                buf_tail = 0;
                start = 0;
                counter = counter.checked_add(1).unwrap(); // cannot fail, otherwise
                                                           // encrypt_next_in_place would have
                                                           // failed too.                                                // encrypt_next_in_place not failing
            } else if read == 0 {
                buf.truncate(buf_tail);

                signer.update(&buf[start..]);
                let sig_final = signer
                    .chain(&counter.to_be_bytes())
                    .chain(&[0x01])
                    .sign(&signing_key.key.0, self.rng);
                bincode::serialize_into(&mut buf, &sig_final)?;

                enc.wrap_last(&mut buf).unwrap();

                w.write_all(&buf).await?;
                break;
            }
        }

        w.flush().await?;
        w.close().await?;

        Ok(())
    }
}

impl<R> Unsealer<R, UnsealerStreamConfig>
where
    R: AsyncRead + Unpin,
{
    /// Create a new [`Unsealer`] that starts reading from an [`AsyncRead`].
    ///
    /// Errors if the bytestream is not a legitimate PostGuard bytestream.
    pub async fn new(mut r: R, pk: &VerifyingKey) -> Result<Self, Error> {
        let mut preamble = [0u8; PREAMBLE_SIZE];
        r.read_exact(&mut preamble)
            .map_err(|_e| Error::NotPostGuard)
            .await?;

        let (version, header_len) = preamble_checked(&preamble)?;
        let mut header_raw = Vec::with_capacity(header_len);

        // Limit reader to not read past header
        let mut r = r.take(header_len as u64);

        r.read_to_end(&mut header_raw)
            .map_err(|_e| Error::ConstraintViolation)
            .await?;

        let mut r = r.into_inner();

        let mut header_sig_len_bytes = [0u8; SIG_SIZE_SIZE];
        r.read_exact(&mut header_sig_len_bytes)
            .map_err(|_e| Error::FormatViolation("no header signature length".to_string()))
            .await?;
        let header_sig_len = u32::from_be_bytes(header_sig_len_bytes);

        let mut header_sig_raw = Vec::with_capacity(header_sig_len as usize);
        let mut r = r.take(header_sig_len as u64);

        r.read_to_end(&mut header_sig_raw).await?;

        let h_sig_ext: SignatureExt = bincode::deserialize(&header_sig_raw)?;

        let verifier = Verifier::default().chain(&header_raw);
        let pub_id = h_sig_ext.pol.derive_ibs()?;

        if !verifier.clone().verify(&pk.0, &h_sig_ext.sig, &pub_id) {
            return Err(Error::IncorrectSignature);
        }

        let header: Header = bincode::deserialize(&header_raw)?;
        let (segment_size, _) = stream_mode_checked(&header)?;

        Ok(Unsealer {
            version,
            header,
            pub_id: h_sig_ext.pol,
            config: UnsealerStreamConfig { segment_size },
            r: r.into_inner(), // This (new) reader is locked to the payload.
            verifier,
            vk: pk.clone(),
        })
    }

    /// Unseal the remaining data (which is now only payload) into an [`AsyncWrite`].
    pub async fn unseal<W: AsyncWrite + Unpin>(
        mut self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
        mut w: W,
    ) -> Result<VerificationResult, Error> {
        let rec_info = self
            .header
            .recipients
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.decaps(usk)?;
        let key = &ss.0[..KEY_SIZE];
        //let aead = Aes128Gcm::new_from_slice(key)?;

        let Algorithm::Aes128Gcm(iv) = self.header.algo;
        let nonce = &iv.0[..STREAM_NONCE_SIZE];

        let mut dec =  Deck::new(&key, &nonce);

        let bufsize: usize = self.config.segment_size as usize + SIG_BYTES + TAG_SIZE;
        let mut buf = vec![0u8; bufsize];
        let mut buf_tail = 0;
        let mut counter: u32 = 0;
        let mut pol_id: Option<(Policy, Identity)> = None;

        fn extract_policy(buf: &mut Vec<u8>) -> Result<Option<(Policy, Identity)>, Error> {
            let pol_len = u32::from_be_bytes(buf[..POL_SIZE_SIZE].try_into()?) as usize;
            let pol_bytes = &buf[POL_SIZE_SIZE..POL_SIZE_SIZE + pol_len];
            let pol: Policy = bincode::deserialize(pol_bytes)?;
            let id = pol.derive_ibs()?;

            buf.drain(..POL_SIZE_SIZE + pol_len);

            Ok(Some((pol, id)))
        }

        fn verify_segment<'a>(
            seg: &'a [u8],
            verifier: &mut Verifier,
            vk: &VerifyingKey,
            id: &Identity,
            counter: u32,
            is_last: bool,
        ) -> Result<&'a [u8], Error> {
            debug_assert!(seg.len() > SIG_BYTES);

            let (m, sig_bytes) = seg.split_at(seg.len() - SIG_BYTES);
            let sig: Signature = bincode::deserialize(sig_bytes)?;
            verifier.update(m);

            if !verifier
                .clone()
                .chain(&counter.to_be_bytes())
                .chain(&[is_last as u8])
                .verify(&vk.0, &sig, id)
            {
                return Err(Error::IncorrectSignature);
            }

            Ok(m)
        }

        loop {
            let read = self.r.read(&mut buf[buf_tail..bufsize]).await?;
            buf_tail += read;

            if buf_tail == bufsize {
                dec.unwrap(&mut buf).unwrap();

                if counter == 0 {
                    pol_id = extract_policy(&mut buf)?;
                }

                let m = verify_segment(
                    &buf,
                    &mut self.verifier,
                    &self.vk,
                    &pol_id.as_ref().unwrap().1,
                    counter,
                    false,
                )?;

                w.write_all(m).await?;

                buf_tail = 0;
                buf.resize(bufsize, 0);
                counter += 1;
            } else if read == 0 {
                buf.truncate(buf_tail);
                dec.unwrap_last(&mut buf).unwrap();

                if counter == 0 {
                    pol_id = extract_policy(&mut buf)?;
                }

                let m = verify_segment(
                    &buf,
                    &mut self.verifier,
                    &self.vk,
                    &pol_id.as_ref().unwrap().1,
                    counter,
                    true,
                )?;

                w.write_all(m).await?;

                break;
            }
        }

        w.close().await?;

        let private_id = pol_id.unwrap().0;
        let private = if self.pub_id == private_id {
            None
        } else {
            Some(private_id)
        };

        Ok(VerificationResult {
            public: self.pub_id,
            private,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Sealer, SealerStreamConfig, Unsealer, UnsealerStreamConfig};
    use crate::client::VerificationResult;
    use crate::error::Error;
    use crate::test::TestSetup;
    use crate::{PREAMBLE_SIZE, SYMMETRIC_CRYPTO_DEFAULT_CHUNK, TAG_SIZE};
    use alloc::string::String;
    use alloc::vec::Vec;
    use futures::{executor::block_on, io::AllowStdIo};
    use rand::{thread_rng, Rng, RngCore};
    use std::io::Cursor;
    use tokio::io::AsyncReadExt;

    const LENGTHS: &[u32] = &[
        1,
        512,
        SYMMETRIC_CRYPTO_DEFAULT_CHUNK - 3,
        SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
        SYMMETRIC_CRYPTO_DEFAULT_CHUNK + 3,
        3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
        3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK + 16,
        3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK - 17,
    ];

    fn seal_helper(setup: &TestSetup, plain: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        let mut input = AllowStdIo::new(Cursor::new(plain));
        let mut output = AllowStdIo::new(Vec::new());

        let signing_key = &setup.signing_keys[0];

        block_on(async {
            Sealer::<_, SealerStreamConfig>::new(
                &setup.ibe_pk,
                &setup.policy,
                &signing_key,
                &mut rng,
            )
            .unwrap()
            .seal(&mut input, &mut output)
            .await
            .unwrap();
        });

        output.into_inner()
    }

    fn unseal_helper(setup: &TestSetup, ct: &[u8]) -> (Vec<u8>, VerificationResult) {
        let mut input = AllowStdIo::new(Cursor::new(ct));
        let mut output = AllowStdIo::new(Vec::new());

        // sometimes decrypt as Bob, sometimes decrypt as Charlie
        let (id, usk_id) = if thread_rng().gen::<bool>() {
            ("Bob", setup.usks[2].clone())
        } else {
            ("Charlie", setup.usks[3].clone())
        };

        let vr = block_on(async {
            let unsealer = Unsealer::<_, UnsealerStreamConfig>::new(&mut input, &setup.ibs_pk)
                .await
                .unwrap();

            // Normally, a user would need to retrieve a usk here via the PKG,
            // but in this case we own the master key pair.
            unsealer.unseal(id, &usk_id, &mut output).await.unwrap()
        });

        (output.into_inner(), vr)
    }

    fn seal_and_unseal(setup: &TestSetup, plain: Vec<u8>) {
        let ct = seal_helper(setup, &plain);
        let (plain2, vr) = unseal_helper(setup, &ct);

        assert_eq!(&plain, &plain2);
        assert_eq!(&vr.public, &setup.signing_keys[0].policy);
        assert_eq!(vr.private, None);
    }

    fn rand_vec(length: usize) -> Vec<u8> {
        let mut vec = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut vec);
        vec
    }

    #[test]
    fn test_reflection_seal_unsealer() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        for l in LENGTHS {
            seal_and_unseal(&setup, rand_vec(*l as usize));
        }
    }

    #[test]
    #[should_panic]
    fn test_corrupt_header() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let plain = rand_vec(100);
        let mut ct = seal_helper(&setup, &plain);

        // Flip a byte that is guaranteed to be in the header.
        ct[PREAMBLE_SIZE + 2] = !ct[PREAMBLE_SIZE + 2];

        // This should panic, because of the header signature.
        let _plain2 = unseal_helper(&setup, &ct);
    }

    #[test]
    #[should_panic]
    fn test_corrupt_payload() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let plain = rand_vec(100);
        let mut ct = seal_helper(&setup, &plain);

        // Flip a byte that is guaranteed to be in the encrypted payload.
        let ct_len = ct.len();
        ct[ct_len - TAG_SIZE - 5] = !ct[ct_len - TAG_SIZE - 5];

        // This should panic, because of the AEAD.
        let _plain2 = unseal_helper(&setup, &ct);
    }

    #[test]
    #[should_panic]
    fn test_corrupt_tag() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let plain = rand_vec(100);
        let mut ct = seal_helper(&setup, &plain);

        let len = ct.len();
        ct[len - 5] = !ct[len - 5];

        // This should panic as well.
        let _plain2 = unseal_helper(&setup, &ct);
    }

    #[tokio::test]
    async fn test_tokio_file() -> Result<(), Error> {
        use futures::AsyncWriteExt;
        use tokio::fs::{File, OpenOptions};
        use tokio_util::compat::TokioAsyncReadCompatExt;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let signing_key = &setup.signing_keys[0];

        let in_name = std::env::temp_dir().join("foo.txt");
        let out_name = std::env::temp_dir().join("foo.enc");
        let orig_name = std::env::temp_dir().join("foo2.txt");

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&in_name)
            .await?
            .compat();

        file.write_all(b"SECRET DATA").await?;
        file.close().await?;

        let mut in_file = File::open(&in_name).await?.compat();
        let mut out_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&out_name)
            .await?
            .compat();

        Sealer::<_, SealerStreamConfig>::new(&setup.ibe_pk, &setup.policy, signing_key, &mut rng)?
            .seal(&mut in_file, &mut out_file)
            .await?;

        in_file.close().await?;
        out_file.close().await?;

        let mut out_file = File::open(&out_name).await?.compat();
        let mut orig_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&orig_name)
            .await?
            .compat();

        let id = "Bob";
        let usk = &setup.usks[2];

        Unsealer::<_, UnsealerStreamConfig>::new(&mut out_file, &setup.ibs_pk)
            .await?
            .unseal(id, usk, &mut orig_file)
            .await?;

        out_file.close().await?;
        orig_file.close().await?;

        let mut buf = String::new();
        File::open(&orig_name)
            .await?
            .read_to_string(&mut buf)
            .await?;

        assert_eq!(buf.as_bytes(), b"SECRET DATA");

        Ok(())
    }

    #[tokio::test]
    async fn test_cursor() -> Result<(), Error> {
        use futures::io::Cursor;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let signing_key = &setup.signing_keys[0];

        let mut input = Cursor::new(b"SECRET DATA");
        let mut encrypted = Vec::new();

        Sealer::<_, SealerStreamConfig>::new(&setup.ibe_pk, &setup.policy, signing_key, &mut rng)?
            .seal(&mut input, &mut encrypted)
            .await?;

        let mut original = Vec::new();
        let id = "Bob";
        let usk = &setup.usks[2];
        Unsealer::<_, UnsealerStreamConfig>::new(&mut Cursor::new(encrypted), &setup.ibs_pk)
            .await?
            .unseal(id, usk, &mut original)
            .await?;

        assert_eq!(input.into_inner().to_vec(), original);
        Ok(())
    }
}
