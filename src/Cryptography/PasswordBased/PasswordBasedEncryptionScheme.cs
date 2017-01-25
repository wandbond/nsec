using System;

namespace NSec.Cryptography.PasswordBased
{
    //
    //  PBES2
    //
    //      Password-Based Encryption Scheme
    //
    //  References
    //
    //      draft-moriarty-pkcs5-v2dot1-04 - PKCS #5: Password-Based
    //          Cryptography Specification Version 2.1
    //
    //  Parameters
    //
    //      PBES2 combines a password-based key derivation function with an
    //      underlying encryption scheme. The key length and any other
    //      parameters for the underlying encryption scheme depend on the
    //      scheme.
    //
    public class PasswordBasedEncryptionScheme
    {
        private readonly AeadAlgorithm _encryptionAlgorithm;
        private readonly PasswordHashAlgorithm _passwordHashAlgorithm;

        public PasswordBasedEncryptionScheme(
            PasswordHashAlgorithm passwordHashAlgorithm,
            AeadAlgorithm encryptionAlgorithm)
        {
            if (passwordHashAlgorithm == null)
                throw new ArgumentNullException(nameof(passwordHashAlgorithm));
            if (encryptionAlgorithm == null)
                throw new ArgumentNullException(nameof(encryptionAlgorithm));

            _passwordHashAlgorithm = passwordHashAlgorithm;
            _encryptionAlgorithm = encryptionAlgorithm;
        }

        public AeadAlgorithm EncryptionAlgorithm => _encryptionAlgorithm;

        public PasswordHashAlgorithm PasswordHashAlgorithm => _passwordHashAlgorithm;

        public byte[] Decrypt(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _encryptionAlgorithm))
            {
                return _encryptionAlgorithm.Decrypt(key, nonce, ReadOnlySpan<byte>.Empty, ciphertext);
            }
        }

        public void Decrypt(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _encryptionAlgorithm))
            {
                _encryptionAlgorithm.Decrypt(key, nonce, ReadOnlySpan<byte>.Empty, ciphertext, plaintext);
            }
        }

        public byte[] Encrypt(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _encryptionAlgorithm))
            {
                return _encryptionAlgorithm.Encrypt(key, nonce, ReadOnlySpan<byte>.Empty, plaintext);
            }
        }

        public void Encrypt(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _encryptionAlgorithm))
            {
                _encryptionAlgorithm.Encrypt(key, nonce, ReadOnlySpan<byte>.Empty, plaintext, ciphertext);
            }
        }

        public bool TryDecrypt(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            out byte[] plaintext)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _encryptionAlgorithm))
            {
                return _encryptionAlgorithm.TryDecrypt(key, nonce, ReadOnlySpan<byte>.Empty, ciphertext, out plaintext);
            }
        }

        public bool TryDecrypt(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _encryptionAlgorithm))
            {
                return _encryptionAlgorithm.TryDecrypt(key, nonce, ReadOnlySpan<byte>.Empty, ciphertext, plaintext);
            }
        }
    }
}
