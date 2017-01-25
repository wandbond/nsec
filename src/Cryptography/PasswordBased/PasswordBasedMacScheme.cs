using System;

namespace NSec.Cryptography.PasswordBased
{
    //
    //  PBMAC1
    //
    //      Password-Based Message Authentication Scheme
    //
    //  References
    //
    //      draft-moriarty-pkcs5-v2dot1-04 - PKCS #5: Password-Based
    //          Cryptography Specification Version 2.1
    //
    //  Parameters
    //
    //      PBMAC1 combines a password-based key derivation function with an
    //      underlying message authentication scheme. The key length and any
    //      other parameters for the underlying message authentication scheme
    //      depend on the scheme.
    //
    public class PasswordBasedMacScheme
    {
        private readonly MacAlgorithm _macAlgorithm;
        private readonly PasswordHashAlgorithm _passwordHashAlgorithm;

        public PasswordBasedMacScheme(
            PasswordHashAlgorithm passwordHashAlgorithm,
            MacAlgorithm macAlgorithm)
        {
            if (passwordHashAlgorithm == null)
                throw new ArgumentNullException(nameof(passwordHashAlgorithm));
            if (macAlgorithm == null)
                throw new ArgumentNullException(nameof(macAlgorithm));

            _passwordHashAlgorithm = passwordHashAlgorithm;
            _macAlgorithm = macAlgorithm;
        }

        public MacAlgorithm MacAlgorithm => _macAlgorithm;

        public PasswordHashAlgorithm PasswordHashAlgorithm => _passwordHashAlgorithm;

        public byte[] Sign(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> data)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _macAlgorithm))
            {
                return _macAlgorithm.Sign(key, nonce, data);
            }
        }

        public byte[] Sign(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> data,
            int macSize)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _macAlgorithm))
            {
                return _macAlgorithm.Sign(key, nonce, data, macSize);
            }
        }

        public void Sign(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> data,
            Span<byte> mac)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _macAlgorithm))
            {
                _macAlgorithm.Sign(key, nonce, data, mac);
            }
        }

        public bool TryVerify(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _macAlgorithm))
            {
                return _macAlgorithm.TryVerify(key, nonce, data, mac);
            }
        }

        public void Verify(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> mac)
        {
            using (Key key = _passwordHashAlgorithm.DeriveKey(password, salt, strength, _macAlgorithm))
            {
                _macAlgorithm.Verify(key, nonce, data, mac);
            }
        }
    }
}
