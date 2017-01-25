using System;
using NSec.Cryptography.Formatting;
using NSec.Cryptography.PasswordBased;

namespace NSec.Cryptography
{
    public enum KeyBlobFormat2
    {
        PkixEncryptedPrivateKey = -302,
        PkixEncryptedPrivateKeyText = -303,
    }

    public static class Key2
    {
        public static byte[] Export(
            this Key @this,
            KeyBlobFormat2 format,
            PasswordBasedEncryptionScheme pbes,
            string password,
            PasswordHashStrength strength)
        {
            if (pbes == null)
                throw new ArgumentNullException(nameof(pbes));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            int maxBlobSize = AlgorithmExtensions.GetKeyBlobSize(@this.Algorithm, format);
            byte[] blob = new byte[maxBlobSize];
            int blobSize = @this.Algorithm.ExportKey(@this, format, pbes, password, strength, blob);
            Array.Resize(ref blob, blobSize);
            return blob;
        }

        public static int Export(
            this Key @this,
            KeyBlobFormat2 format,
            PasswordBasedEncryptionScheme pbes,
            string password,
            PasswordHashStrength strength,
            Span<byte> blob)
        {
            if (pbes == null)
                throw new ArgumentNullException(nameof(pbes));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            return @this.Algorithm.ExportKey(@this, format, pbes, password, strength, blob);
        }

        public static Key Import(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat2 format,
            KeyFlags flags,
            PasswordBasedEncryptionScheme pbes,
            string password)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (pbes == null)
                throw new ArgumentNullException(nameof(pbes));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            if (!algorithm.TryImportKey(blob, format, flags, pbes, password, out Key result))
            {
                throw new FormatException();
            }

            return result;
        }

        public static bool TryImport(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat2 format,
            KeyFlags flags,
            PasswordBasedEncryptionScheme pbes,
            string password,
            out Key result)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (pbes == null)
                throw new ArgumentNullException(nameof(pbes));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            return algorithm.TryImportKey(blob, format, flags, pbes, password, out result);
        }
    }

    internal static class AeadAlgorithmExtensions
    {
        private static readonly Oid s_aes = new Oid(2, 16, 840, 1, 101, 3, 4, 1, 46);
        private static readonly Oid s_chacha = new Oid(1, 2, 840, 113549, 1, 9, 16, 3, 99999);

        internal static bool TryReadAlgorithmIdentifier(
            this AeadAlgorithm @this,
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> nonce)
        {
            if (@this is Aes256Gcm)
            {
                reader.BeginSequence();
                ReadOnlySpan<byte> oid = reader.ObjectIdentifier();
                reader.BeginSequence();
                nonce = reader.OctetString();
                reader.End();
                reader.End();

                return reader.Success
                    && oid.SequenceEqual(s_aes.Bytes)
                    && (nonce.Length >= @this.MinNonceSize)
                    && (nonce.Length <= @this.MinNonceSize);
            }
            else if (@this is ChaCha20Poly1305)
            {
                reader.BeginSequence();
                ReadOnlySpan<byte> oid = reader.ObjectIdentifier();
                nonce = reader.OctetString();
                reader.End();

                return reader.Success
                    && oid.SequenceEqual(s_chacha.Bytes)
                    && (nonce.Length >= @this.MinNonceSize)
                    && (nonce.Length <= @this.MinNonceSize);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        internal static void WriteAlgorithmIdentifier(
            this AeadAlgorithm @this,
            ref Asn1Writer writer,
            ReadOnlySpan<byte> nonce)
        {
            if (@this is Aes256Gcm)
            {
                writer.End();
                writer.End();
                writer.OctetString(nonce);
                writer.BeginSequence();
                writer.ObjectIdentifier(s_aes.Bytes);
                writer.BeginSequence();
            }
            else if (@this is ChaCha20Poly1305)
            {
                writer.End();
                writer.OctetString(nonce);
                writer.ObjectIdentifier(s_chacha.Bytes);
                writer.BeginSequence();
            }
            else
            {
                throw new NotSupportedException();
            }
        }
    }

    internal static class AlgorithmExtensions
    {
        internal static int ExportKey(
            this Algorithm @this,
            Key key,
            KeyBlobFormat2 format,
            PasswordBasedEncryptionScheme pbes,
            string password,
            PasswordHashStrength strength,
            Span<byte> blob)
        {
            switch (format)
            {
            case KeyBlobFormat2.PkixEncryptedPrivateKey:
                return PkixEncryptedPrivateKeyFormatter.EncryptKey(pbes, password, strength, key, blob);
            case KeyBlobFormat2.PkixEncryptedPrivateKeyText:
                return PkixEncryptedPrivateKeyFormatter.EncryptKeyText(pbes, password, strength, key, blob);
            default:
                throw new FormatException();
            }
        }

        internal static int GetKeyBlobSize(
            this Algorithm @this,
            KeyBlobFormat2 format)
        {
            switch (format)
            {
            case KeyBlobFormat2.PkixEncryptedPrivateKey:
                return PkixEncryptedPrivateKeyFormatter.MaxBlobSize;
            case KeyBlobFormat2.PkixEncryptedPrivateKeyText:
                return PkixEncryptedPrivateKeyFormatter.MaxBlobTextSize;
            default:
                throw new FormatException();
            }
        }

        internal static bool TryImportKey(
            this Algorithm @this,
            ReadOnlySpan<byte> blob,
            KeyBlobFormat2 format,
            KeyFlags flags,
            PasswordBasedEncryptionScheme pbes,
            string password,
            out Key result)
        {
            switch (format)
            {
            case KeyBlobFormat2.PkixEncryptedPrivateKey:
                return PkixEncryptedPrivateKeyFormatter.TryDecryptKey(pbes, password, blob, @this, flags, out result);
            case KeyBlobFormat2.PkixEncryptedPrivateKeyText:
                return PkixEncryptedPrivateKeyFormatter.TryDecryptKeyText(pbes, password, blob, @this, flags, out result);
            default:
                result = null;
                return false;
            }
        }
    }

    internal static class PasswordBasedEncryptionSchemeExtensions
    {
        private static readonly Oid s_pbes2 = new Oid(1, 2, 840, 113549, 1, 5, 13);

        internal static bool TryReadAlgorithmIdentifier(
            this PasswordBasedEncryptionScheme @this,
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> salt,
            out PasswordHashStrength strength,
            out ReadOnlySpan<byte> nonce)
        {
            bool success = true;
            reader.BeginSequence();
            success &= reader.ObjectIdentifier().SequenceEqual(s_pbes2.Bytes);
            reader.BeginSequence();
            success &= @this.PasswordHashAlgorithm.TryReadAlgorithmIdentifier(ref reader, out salt, out strength);
            success &= @this.EncryptionAlgorithm.TryReadAlgorithmIdentifier(ref reader, out nonce);
            reader.End();
            reader.End();
            success &= reader.Success;
            return success;
        }

        internal static void WriteAlgorithmIdentifier(
            this PasswordBasedEncryptionScheme @this,
            ref Asn1Writer writer,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength,
            ReadOnlySpan<byte> nonce)
        {
            writer.End();
            writer.End();
            @this.EncryptionAlgorithm.WriteAlgorithmIdentifier(ref writer, nonce);
            @this.PasswordHashAlgorithm.WriteAlgorithmIdentifier(ref writer, salt, strength);
            writer.BeginSequence();
            writer.ObjectIdentifier(s_pbes2.Bytes);
            writer.BeginSequence();
        }
    }

    internal static class PasswordHashAlgorithmExtensions
    {
        private static readonly Oid s_scrypt = new Oid(1, 3, 6, 1, 4, 1, 11591, 4, 11);

        internal static bool TryReadAlgorithmIdentifier(
            this PasswordHashAlgorithm @this,
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> salt,
            out PasswordHashStrength strength)
        {
            if (@this is Scrypt)
            {
                reader.BeginSequence();
                ReadOnlySpan<byte> oid = reader.ObjectIdentifier();
                reader.BeginSequence();
                salt = reader.OctetString();
                long cost = reader.Integer64();
                int blockSize = reader.Integer32();
                int parallelization = reader.Integer32();
                reader.End();
                reader.End();

                // libsodium does not allow passing cost, blockSize and 
                // parallelization directly, to the scrypt implementation, so
                // we search for an opslimit and memlimit pair that yields the
                // same values.
                strength = 0;
                for (int i = 6; i <= 24; i += 2)
                {
                    @this.PickParameters(i, out ulong opslimit, out UIntPtr memlimit);
                    Scrypt.PickParameters(opslimit, memlimit, out int N_log2, out int p, out int r);
                    if ((cost == 1L << N_log2) &&
                        (blockSize == r) &&
                        (parallelization == p))
                    {
                        strength = (PasswordHashStrength)i;
                        break;
                    }
                }

                return reader.Success
                    && oid.SequenceEqual(s_scrypt.Bytes)
                    && (salt.Length == @this.SaltSize)
                    && (strength >= PasswordHashStrength.Interactive)
                    && (strength <= (PasswordHashStrength)30); // TODO: strength is an untrusted input; need to pick a reasonable limit
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        internal static void WriteAlgorithmIdentifier(
            this PasswordHashAlgorithm @this,
            ref Asn1Writer writer,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength)
        {
            if (@this is Scrypt)
            {
                @this.PickParameters((int)strength, out ulong opslimit, out UIntPtr memlimit);
                Scrypt.PickParameters(opslimit, memlimit, out int N_log2, out int p, out int r);

                writer.End();
                writer.End();
                writer.Integer(p);
                writer.Integer(r);
                writer.Integer(1L << N_log2);
                writer.OctetString(salt);
                writer.BeginSequence();
                writer.ObjectIdentifier(s_scrypt.Bytes);
                writer.BeginSequence();
            }
            else
            {
                throw new NotSupportedException();
            }
        }
    }
}
