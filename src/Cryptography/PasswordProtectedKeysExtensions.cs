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
}
