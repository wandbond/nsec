using System;
using NSec.Cryptography.PasswordBased;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    // RFC 5958
    internal static class PkixEncryptedPrivateKeyFormatter
    {
        public const int MaxBlobSize = 256;
        public const int MaxBlobTextSize = 448;

        private static readonly byte[] s_beginLabel =
        {
            // "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x42, 0x45, 0x47,
            0x49, 0x4E, 0x20, 0x45, 0x4E, 0x43, 0x52, 0x59,
            0x50, 0x54, 0x45, 0x44, 0x20, 0x50, 0x52, 0x49,
            0x56, 0x41, 0x54, 0x45, 0x20, 0x4B, 0x45, 0x59,
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D,
        };

        private static readonly byte[] s_endLabel =
        {
            // "-----END ENCRYPTED PRIVATE KEY-----"
            0x2D, 0x2D, 0x2D, 0x2D, 0x2D, 0x45, 0x4E, 0x44,
            0x20, 0x45, 0x4E, 0x43, 0x52, 0x59, 0x50, 0x54,
            0x45, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41,
            0x54, 0x45, 0x20, 0x4B, 0x45, 0x59, 0x2D, 0x2D,
            0x2D, 0x2D, 0x2D,
        };

        public static int EncryptKey(
            PasswordBasedEncryptionScheme pbes,
            string password,
            PasswordHashStrength strength,
            Key key,
            Span<byte> blob)
        {
            int maxBlobSize = Key.GetKeyBlobSize(key.Algorithm, KeyBlobFormat.PkixPrivateKey);

            ReadOnlySpan<byte> salt = SecureRandom.GenerateBytes(pbes.PasswordHashAlgorithm.SaltSize);
            ReadOnlySpan<byte> nonce = SecureRandom.GenerateBytes(pbes.EncryptionAlgorithm.NonceSize);
            ReadOnlySpan<byte> ciphertext;

            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[maxBlobSize];
                    temp = new Span<byte>(pointer, maxBlobSize);
                }

                int blobSize = key.Export(KeyBlobFormat.PkixPrivateKey, temp);

                ciphertext = pbes.Encrypt(password, salt, strength, nonce, temp.Slice(0, blobSize));
            }
            finally
            {
                sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
            }

            pbes.PasswordHashAlgorithm.PickParameters((int)strength, out PasswordHashParameters parameters);

            Asn1Writer writer = new Asn1Writer(ref blob);
            writer.End();
            writer.OctetString(ciphertext);
            pbes.WriteAlgorithmIdentifier(ref writer, salt, ref parameters, nonce);
            writer.BeginSequence();
            writer.Bytes.CopyTo(blob);
            return writer.Bytes.Length;
        }

        public static int EncryptKeyText(
            PasswordBasedEncryptionScheme pbes,
            string password,
            PasswordHashStrength strength,
            Key key,
            Span<byte> blob)
        {
            Span<byte> temp = new byte[MaxBlobSize];
            int length = EncryptKey(pbes, password, strength, key, temp);
            int encodedLength = Armor.GetEncodedSize(length, s_beginLabel, s_endLabel);

            if (blob.Length < encodedLength)
            {
                throw new ArgumentException(Error.ArgumentExceptionMessage, nameof(blob)); // not enough space
            }

            Armor.Encode(temp.Slice(0, length), s_beginLabel, s_endLabel, blob.Slice(0, encodedLength));
            return encodedLength;
        }

        public static bool TryDecryptKey(
            PasswordBasedEncryptionScheme pbes,
            string password,
            ReadOnlySpan<byte> blob,
            Algorithm algorithm,
            KeyFlags flags,
            out Key result)
        {
            Asn1Reader reader = new Asn1Reader(ref blob);
            bool success = true;
            reader.BeginSequence();
            success &= pbes.TryReadAlgorithmIdentifier(ref reader, out ReadOnlySpan<byte> salt, out PasswordHashParameters parameters, out ReadOnlySpan<byte> nonce);
            ReadOnlySpan<byte> ciphertext = reader.OctetString();
            reader.End();
            success &= reader.SuccessComplete;

            int maxBlobSize = Key.GetKeyBlobSize(algorithm, KeyBlobFormat.PkixPrivateKey);
            int blobSize = ciphertext.Length - pbes.EncryptionAlgorithm.TagSize;

            if (!success || blobSize < 0 || blobSize > maxBlobSize)
            {
                result = null;
                return false;
            }

            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[blobSize];
                    temp = new Span<byte>(pointer, blobSize);
                }

                if (!pbes.TryDecrypt(password, salt, ref parameters, nonce, ciphertext, temp))
                {
                    result = null;
                    return false;
                }

                return Key.TryImport(algorithm, temp, KeyBlobFormat.PkixPrivateKey, flags, out result);
            }
            finally
            {
                sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
            }
        }

        public static bool TryDecryptKeyText(
            PasswordBasedEncryptionScheme pbes,
            string password,
            ReadOnlySpan<byte> blob,
            Algorithm algorithm,
            KeyFlags flags,
            out Key result)
        {
            Span<byte> temp = new byte[MaxBlobSize];

            if (!Armor.TryDecode(blob, s_beginLabel, s_endLabel, temp, out int length))
            {
                result = null;
                return false;
            }

            return TryDecryptKey(pbes, password, temp.Slice(0, length), algorithm, flags, out result);
        }
    }
}
