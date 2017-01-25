using System;
using NSec.Cryptography.PasswordBased;
using static Interop.Libsodium;

namespace NSec.Cryptography.Formatting
{
    internal static class PkixEncryptedPrivateKeyFormatter
    {
        public const int MaxBlobSize = 256;

        public static int EncryptKey(
            PasswordBasedEncryptionScheme pbes,
            string password,
            PasswordHashStrength strength,
            Key key,
            Span<byte> blob)
        {
            int maxBlobSize = Key.GetKeyBlobSize(key.Algorithm, KeyBlobFormat.PkixPrivateKey);

            ReadOnlySpan<byte> salt = SecureRandom.GenerateBytes(pbes.PasswordHashAlgorithm.SaltSize);
            ReadOnlySpan<byte> nonce = SecureRandom.GenerateBytes(pbes.EncryptionAlgorithm.MaxNonceSize);
            ReadOnlySpan<byte> ciphertext;

            Span<byte> temp;
            try
            {
                unsafe
                {
                    byte* pointer = stackalloc byte[maxBlobSize];
                    temp = new Span<byte>(pointer, maxBlobSize);
                }

                int blobSize = key.Algorithm.ExportKey(key.Handle, KeyBlobFormat.PkixPrivateKey, temp);

                ciphertext = pbes.Encrypt(password, salt, strength, nonce, temp.Slice(0, blobSize));
            }
            finally
            {
                sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
            }

            Asn1Writer writer = new Asn1Writer(ref blob);
            writer.End();
            writer.OctetString(ciphertext);
            pbes.WriteAlgorithmIdentifier(ref writer, salt, strength, nonce);
            writer.BeginSequence();
            writer.Bytes.CopyTo(blob);
            return writer.Bytes.Length;
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
            success &= pbes.TryReadAlgorithmIdentifier(ref reader, out ReadOnlySpan<byte> salt, out PasswordHashStrength strength, out ReadOnlySpan<byte> nonce);
            ReadOnlySpan<byte> ciphertext = reader.OctetString();
            reader.End();
            success &= reader.Success;

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

                if (!pbes.TryDecrypt(password, salt, strength, nonce, ciphertext, temp))
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
    }
}
