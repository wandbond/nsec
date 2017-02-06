using System;
using NSec.Cryptography.Formatting;

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

        private static readonly Oid s_oid = new Oid(1, 2, 840, 113549, 1, 5, 13);

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

        internal bool TryDecrypt(
            string password,
            ReadOnlySpan<byte> salt,
            ref PasswordHashParameters parameters,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, ref parameters, _encryptionAlgorithm))
            {
                return _encryptionAlgorithm.TryDecrypt(key, nonce, ReadOnlySpan<byte>.Empty, ciphertext, plaintext);
            }
        }

        internal bool TryReadAlgorithmIdentifier(
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> salt,
            out PasswordHashParameters parameters,
            out ReadOnlySpan<byte> nonce)
        {
            bool success = true;
            reader.BeginSequence();
            success &= reader.ObjectIdentifier().SequenceEqual(s_oid.Bytes);
            reader.BeginSequence();
            success &= PasswordHashAlgorithm.TryReadAlgorithmIdentifier(ref reader, out salt, out parameters);
            success &= EncryptionAlgorithm.TryReadAlgorithmIdentifier(ref reader, out nonce);
            reader.End();
            reader.End();
            success &= reader.Success;
            return success;
        }

        internal void WriteAlgorithmIdentifier(
            ref Asn1Writer writer,
            ReadOnlySpan<byte> salt,
            ref PasswordHashParameters parameters,
            ReadOnlySpan<byte> nonce)
        {
            writer.End();
            writer.End();
            EncryptionAlgorithm.WriteAlgorithmIdentifier(ref writer, nonce);
            PasswordHashAlgorithm.WriteAlgorithmIdentifier(ref writer, salt, ref parameters);
            writer.BeginSequence();
            writer.ObjectIdentifier(s_oid.Bytes);
            writer.BeginSequence();
        }
    }
}
