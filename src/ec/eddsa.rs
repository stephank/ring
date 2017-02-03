// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! EdDSA Signatures.

use {bssl, c, error, private, rand, signature};
use untrusted;

/// Parameters for EdDSA signing and verification.
pub struct EdDSAParameters;

/// An Ed25519 public key, for verifying signatures.
pub struct Ed25519PublicKey<'a>(&'a [u8]);

impl<'a> Ed25519PublicKey<'a> {
    /// Create a new public key referencing the given of bytes.
    /// The slice must contain 32 little-endian-encoded bytes.
    pub fn from_bytes(public_key: &[u8])
                      -> Result<Ed25519PublicKey, error::Unspecified> {
        if public_key.len() != 32 {
            return Err(error::Unspecified);
        }
        Ok(Ed25519PublicKey(public_key))
    }

    /// Returns a reference to the little-endian-encoded public key bytes.
    pub fn public_key_bytes(&self) -> &[u8] { self.0 }

    /// Verify a message signature using this public key.
    pub fn verify(&self, msg: untrusted::Input, signature: untrusted::Input)
                  -> Result<(), error::Unspecified> {
        let msg = msg.as_slice_less_safe();
        let signature = signature.as_slice_less_safe();
        bssl::map_result(unsafe {
            GFp_ed25519_verify(msg.as_ptr(), msg.len(), signature.as_ptr(),
                               self.0.as_ptr())
        })
    }
}

/// An Ed25519 key pair, for signing.
pub struct Ed25519KeyPair {
    private_public: [u8; 64],
}

impl Ed25519KeyPair {
    /// Generates a new random key pair.
    pub fn generate(rng: &rand::SecureRandom)
                    -> Result<Ed25519KeyPair, error::Unspecified> {
        let mut private_key: [u8; 32] = [0; 32];
        let mut public_key: [u8; 32] = [0; 32];
        try!(rng.fill(&mut private_key));
        unsafe {
            GFp_ed25519_public_from_private(public_key.as_mut_ptr(),
                                            private_key.as_ptr());
        }
        let key_pair =
            try!(Ed25519KeyPair::from_bytes_unchecked(&private_key,
                                                      &public_key));
        Ok(key_pair)
    }

    /// Copies key data from the given slices to create a new key pair. The
    /// first slice must hold the private key and the second slice must hold
    /// the public key. Both slices must contain 32 little-endian-encoded
    /// bytes.
    ///
    /// This is intended for use by code that deserializes key pairs.
    ///
    /// The private and public keys will be verified to be consistent. This
    /// helps protect, for example, against the accidental swapping of the
    /// public and private components of the key pair. This also detects
    /// corruption that might have occurred during storage of the key pair.
    pub fn from_bytes(private_key: &[u8], public_key: &[u8])
                      -> Result<Ed25519KeyPair, error::Unspecified> {
        let pair = try!(Ed25519KeyPair::from_bytes_unchecked(private_key,
                                                             public_key));
        let mut public_key_check = [0; 32];
        unsafe {
            GFp_ed25519_public_from_private(public_key_check.as_mut_ptr(),
                                            pair.private_public.as_ptr());
        }
        if public_key != public_key_check {
            return Err(error::Unspecified);
        }
        Ok(pair)
    }

    fn from_bytes_unchecked(private_key: &[u8], public_key: &[u8])
                            -> Result<Ed25519KeyPair, error::Unspecified> {
        if private_key.len() != 32 {
            return Err(error::Unspecified);
        }
        if public_key.len() != 32 {
            return Err(error::Unspecified);
        }
        let mut pair = Ed25519KeyPair { private_public: [0; 64] };
        for i in 0..32 {
            pair.private_public[i] = private_key[i];
            pair.private_public[32 + i] = public_key[i];
        }
        Ok(pair)
    }

    /// Returns a reference to the little-endian-encoded private key bytes.
    pub fn private_key_bytes(&self) -> &[u8] { &self.private_public[..32] }

    /// Returns a reference to the little-endian-encoded public key bytes.
    pub fn public_key_bytes(&self) -> &[u8] { &self.private_public[32..] }

    /// Creates a new `Ed25519PublicKey` referencing this key pair.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes(self.public_key_bytes()).unwrap()
    }

    /// Returns the signature of the message `msg`.
    pub fn sign(&self, msg: &[u8]) -> signature::Signature {
        let mut signature_bytes = [0u8; 64];
        unsafe {
            GFp_ed25519_sign(signature_bytes.as_mut_ptr(), msg.as_ptr(),
                             msg.len(), self.private_public.as_ptr());
        }
        signature::Signature::new(signature_bytes)
    }

    /// Verify a message signature using the public key of this key pair.
    pub fn verify(&self, msg: untrusted::Input, signature: untrusted::Input)
                  -> Result<(), error::Unspecified> {
        self.public_key().verify(msg, signature)
    }
}


/// Verification of [Ed25519] signatures.
///
/// Ed25519 uses SHA-512 as the digest algorithm.
///
/// [Ed25519]: https://ed25519.cr.yp.to/
pub static ED25519: EdDSAParameters = EdDSAParameters {};

impl signature::VerificationAlgorithm for EdDSAParameters {
    fn verify(&self, public_key: untrusted::Input, msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), error::Unspecified> {
        if signature.len() != 64 {
            return Err(error::Unspecified);
        }
        let public_key = try!(Ed25519PublicKey::from_bytes(
                              public_key.as_slice_less_safe()));
        public_key.verify(msg, signature)
    }
}

impl private::Private for EdDSAParameters {}


extern  {
    fn GFp_ed25519_public_from_private(out: *mut u8/*[32]*/,
                                       in_: *const u8/*[32]*/);

    fn GFp_ed25519_sign(out_sig: *mut u8/*[64]*/, message: *const u8,
                        message_len: c::size_t, private_key: *const u8/*[64]*/);

    fn GFp_ed25519_verify(message: *const u8, message_len: c::size_t,
                          signature: *const u8/*[64]*/,
                          public_key: *const u8/*[32]*/) -> c::int;
}


#[cfg(test)]
mod tests {
    use {test, rand, signature};
    use super::Ed25519KeyPair;
    use untrusted;

    /// Test vectors from BoringSSL.
    #[test]
    fn test_signature_ed25519() {
        test::from_file("src/ec/ed25519_tests.txt", |section, test_case| {
            assert_eq!(section, "");
            let private_key = test_case.consume_bytes("PRIV");
            assert_eq!(64, private_key.len());
            let public_key = test_case.consume_bytes("PUB");
            assert_eq!(32, public_key.len());
            let msg = test_case.consume_bytes("MESSAGE");
            let expected_sig = test_case.consume_bytes("SIG");

            let key_pair = Ed25519KeyPair::from_bytes(&private_key[..32],
                                                      &public_key).unwrap();
            let actual_sig = key_pair.sign(&msg);
            assert_eq!(&expected_sig[..], actual_sig.as_slice());

            let public_key = untrusted::Input::from(&public_key);
            let msg = untrusted::Input::from(&msg);
            let expected_sig = untrusted::Input::from(&expected_sig);

            assert!(signature::verify(&signature::ED25519, public_key,
                                      msg, expected_sig).is_ok());

            Ok(())
        });
    }

    #[test]
    fn test_ed25519_from_bytes_misuse() {
        let rng = rand::SystemRandom::new();
        let key_pair = Ed25519KeyPair::generate(&rng).unwrap();
        let private_key = key_pair.private_key_bytes();
        let public_key = key_pair.public_key_bytes();

        assert!(Ed25519KeyPair::from_bytes(private_key,
                                           public_key).is_ok());

        // Truncated private key.
        assert!(Ed25519KeyPair::from_bytes(&private_key[..31],
                                           public_key).is_err());

        // Truncated public key.
        assert!(Ed25519KeyPair::from_bytes(private_key,
                                           &public_key[..31]).is_err());

        // Swapped public and private key.
        assert!(Ed25519KeyPair::from_bytes(public_key,
                                           private_key).is_err());
    }
}
