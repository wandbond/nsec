using System;
using System.Diagnostics;
using System.Text;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A password hashing algorithm
    //
    //  Examples
    //
    //      | Algorithm | Reference |
    //      | --------- | --------- |
    //      | Argon2i   | [1]       |
    //      | scrypt    | RFC 7914  |
    //
    //      [1] draft-irtf-cfrg-argon2-01
    //
    public abstract class PasswordHashAlgorithm : Algorithm
    {
        private readonly int _maxOutputSize;
        private readonly int _maxStrength;
        private readonly int _passwordHashSize;
        private readonly int _saltSize;

        internal PasswordHashAlgorithm(
            int passwordHashSize,
            int saltSize,
            int maxStrength,
            int maxOutputSize)
        {
            Debug.Assert(passwordHashSize > 0);
            Debug.Assert(saltSize > 0);
            Debug.Assert(maxStrength >= 6);
            Debug.Assert(maxOutputSize > 0);

            _passwordHashSize = passwordHashSize;
            _saltSize = saltSize;
            _maxStrength = maxStrength;
            _maxOutputSize = maxOutputSize;
        }

        public int MaxOutputSize => _maxOutputSize;

        public int SaltSize => _saltSize;

        public byte[] DeriveBytes(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            int count)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (salt.Length != _saltSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
            if (strength < PasswordHashStrength.Interactive)
                throw new ArgumentOutOfRangeException(nameof(strength));
            if (strength > (PasswordHashStrength)_maxStrength)
                throw new ArgumentOutOfRangeException(nameof(strength));
            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count > _maxOutputSize)
                throw new ArgumentOutOfRangeException(nameof(count));
            if (count == 0)
                return new byte[0];

            PickParameters((int)strength, out PasswordHashParameters parameters);
            ReadOnlySpan<byte> utf8Password = Encoding.UTF8.GetBytes(password); // TODO: avoid placing sensitive data in managed memory

            byte[] bytes = new byte[count];
            if (!TryDeriveBytesCore(utf8Password, salt, ref parameters, bytes))
            {
                throw new CryptographicException();
            }
            return bytes;
        }

        public void DeriveBytes(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            Span<byte> bytes)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (salt.Length != _saltSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
            if (strength < PasswordHashStrength.Interactive)
                throw new ArgumentOutOfRangeException(nameof(strength));
            if (strength > (PasswordHashStrength)_maxStrength)
                throw new ArgumentOutOfRangeException(nameof(strength));
            if (bytes.Length > _maxOutputSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(bytes));
            if (bytes.IsEmpty)
                return;

            PickParameters((int)strength, out PasswordHashParameters parameters);
            ReadOnlySpan<byte> utf8Password = Encoding.UTF8.GetBytes(password); // TODO: avoid placing sensitive data in managed memory

            if (!TryDeriveBytesCore(utf8Password, salt, ref parameters, bytes))
            {
                throw new CryptographicException();
            }
        }

        public Key DeriveKey(
            string password,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            Algorithm algorithm,
            KeyFlags flags = KeyFlags.None)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (salt.Length != _saltSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(salt));
            if (strength < PasswordHashStrength.Interactive)
                throw new ArgumentOutOfRangeException(nameof(strength));
            if (strength > (PasswordHashStrength)_maxStrength)
                throw new ArgumentOutOfRangeException(nameof(strength));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            int keySize = algorithm.GetDefaultKeySize();
            if (keySize > _maxOutputSize)
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(algorithm));

            PickParameters((int)strength, out PasswordHashParameters parameters);
            ReadOnlySpan<byte> utf8Password = Encoding.UTF8.GetBytes(password); // TODO: avoid placing sensitive data in managed memory

            SecureMemoryHandle keyHandle = null;
            byte[] publicKeyBytes = null;
            bool success = false;

            try
            {
                SecureMemoryHandle.Alloc(keySize, out keyHandle);
                if (!TryDeriveKeyCore(utf8Password, salt, ref parameters, keyHandle))
                {
                    throw new CryptographicException();
                }
                algorithm.CreateKey(keyHandle, out publicKeyBytes);
                success = true;
            }
            finally
            {
                if (!success && keyHandle != null)
                {
                    keyHandle.Dispose();
                }
            }

            return new Key(algorithm, flags, keyHandle, publicKeyBytes);
        }

        public string HashPassword(
            string password,
            PasswordHashStrength strength)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (strength < PasswordHashStrength.Interactive)
                throw new ArgumentOutOfRangeException(nameof(strength));
            if (strength > (PasswordHashStrength)_maxStrength)
                throw new ArgumentOutOfRangeException(nameof(strength));

            PickParameters((int)strength, out ulong opslimit, out UIntPtr memlimit);
            ReadOnlySpan<byte> utf8Password = Encoding.UTF8.GetBytes(password); // TODO: avoid placing sensitive data in managed memory

            sbyte[] hash = new sbyte[_passwordHashSize];

            if (!TryHashPasswordCore(utf8Password, opslimit, memlimit, hash))
            {
                throw new CryptographicException();
            }

            return ConvertToString(hash, _passwordHashSize);
        }

        public bool TryVerifyPassword(
            string password,
            string passwordHash)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (passwordHash == null)
                throw new ArgumentNullException(nameof(passwordHash));
            if (passwordHash.Length >= _passwordHashSize)
                return false;

            ReadOnlySpan<byte> utf8Password = Encoding.UTF8.GetBytes(password); // TODO: avoid placing sensitive data in managed memory 

            sbyte[] hash = new sbyte[_passwordHashSize];

            return TryConvertToAscii(passwordHash, hash)
                && TryVerifyPasswordCore(utf8Password, hash);
        }

        public void VerifyPassword(
            string password,
            string passwordHash)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (passwordHash == null)
                throw new ArgumentNullException(nameof(passwordHash));
            if (passwordHash.Length >= _passwordHashSize)
                throw new FormatException();

            ReadOnlySpan<byte> utf8Password = Encoding.UTF8.GetBytes(password); // TODO: avoid placing sensitive data in managed memory 

            sbyte[] hash = new sbyte[_passwordHashSize];

            if (!TryConvertToAscii(passwordHash, hash))
            {
                throw new FormatException();
            }

            if (!TryVerifyPasswordCore(utf8Password, hash))
            {
                throw new CryptographicException();
            }
        }

        internal abstract void PickParameters(
            int strength,
            out ulong opslimit,
            out UIntPtr memlimit);

        internal abstract void PickParameters(
            int strength,
            out PasswordHashParameters parameters);

        internal abstract bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ref PasswordHashParameters parameters,
            Span<byte> bytes);

        internal virtual bool TryDeriveKeyCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ref PasswordHashParameters parameters,
            SecureMemoryHandle keyHandle)
        {
            bool addedRef = false;
            try
            {
                keyHandle.DangerousAddRef(ref addedRef);

                return TryDeriveBytesCore(password, salt, ref parameters, keyHandle.DangerousGetSpan());
            }
            finally
            {
                if (addedRef)
                {
                    keyHandle.DangerousRelease();
                }
            }
        }

        internal abstract bool TryHashPasswordCore(
            ReadOnlySpan<byte> password,
            ulong opslimit,
            UIntPtr memlimit,
            Span<sbyte> passwordHash);

        internal virtual bool TryReadAlgorithmIdentifier(
           ref Asn1Reader reader,
           out ReadOnlySpan<byte> salt,
           out PasswordHashParameters parameters)
        {
            throw new NotSupportedException();
        }

        internal abstract bool TryVerifyPasswordCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<sbyte> passwordHash);

        internal virtual void WriteAlgorithmIdentifier(
            ref Asn1Writer writer,
            ReadOnlySpan<byte> salt,
            ref PasswordHashParameters parameters)
        {
            throw new NotSupportedException();
        }

        private static string ConvertToString(sbyte[] ascii, int passwordHashSize)
        {
            char[] buffer = new char[passwordHashSize];
            int i;

            for (i = 0; i < ascii.Length; i++)
            {
                // The pwhash output is null-terminated, so we break on the
                // first 0.
                if (ascii[i] == 0)
                {
                    break;
                }

                // The pwhash output is an array of *signed* bytes; non-ASCII
                // characters are negative. There should only be printable ASCII
                // characters.
                Debug.Assert(ascii[i] > ' ');
                buffer[i] = (char)ascii[i];
            }

            return new string(buffer, 0, i);
        }

        private static bool TryConvertToAscii(string str, Span<sbyte> ascii)
        {
            for (int i = 0; i < str.Length; i++)
            {
                int ch = str[i];
                if (0 >= ch || ch >= 128)
                {
                    return false;
                }
                ascii[i] = (sbyte)ch;
            }
            return true;
        }
    }
}
