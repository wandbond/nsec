using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  AES256-GCM
    //
    //      Authenticated Encryption with Associated Data (AEAD) algorithm
    //      based on the Advanced Encryption Standard (AES) in Galois/Counter
    //      Mode (GCM) with 256-bit keys
    //
    //  References:
    //
    //      FIPS 197 - Advanced Encryption Standard (AES)
    //
    //      NIST SP 800-38D - Recommendation for Block Cipher Modes of
    //          Operation: Galois/Counter Mode (GCM) and GMAC
    //
    //      RFC 5116 - An Interface and Algorithms for Authenticated Encryption
    //
    //      RFC 5084 - Using AES-CCM and AES-GCM Authenticated Encryption in the
    //          Cryptographic Message Syntax (CMS)
    //
    //  Parameters:
    //
    //      Key Size - 32 bytes.
    //
    //      Nonce Size - 12 bytes.
    //
    //      Tag Size - 16 bytes.
    //
    //      Plaintext Size - Between 0 and 2^36-31 bytes. (A Span<byte> can hold
    //          only up to 2^31-1 bytes.)
    //
    //      Associated Data Size - Between 0 and 2^61-1 bytes.
    //
    //      Ciphertext Size - The ciphertext always has the size of the
    //          plaintext plus the tag size.
    //
    public sealed class Aes256Gcm : AeadAlgorithm
    {
        private static readonly Lazy<int> s_isAvailable = new Lazy<int>(new Func<int>(crypto_aead_aes256gcm_is_available));

        private static readonly KeyFormatter s_nsecKeyFormatter =
            new KeyFormatter(crypto_aead_aes256gcm_KEYBYTES, new byte[]
        {
            0x7F, 0x31, 0x44, crypto_aead_aes256gcm_KEYBYTES,
        });

        private static readonly Oid s_oid = new Oid(2, 16, 840, 1, 101, 3, 4, 1, 46);

        private static readonly KeyFormatter s_rawKeyFormatter =
            new KeyFormatter(crypto_aead_aes256gcm_KEYBYTES, new byte[] { });

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        private static readonly KeyBlobFormat[] s_supportedKeyBlobFormats =
        {
            KeyBlobFormat.NSecSymmetricKey,
            KeyBlobFormat.RawSymmetricKey,
        };

        public Aes256Gcm() : base(
            keySize: crypto_aead_aes256gcm_KEYBYTES,
            nonceSize: crypto_aead_aes256gcm_NPUBBYTES,
            tagSize: crypto_aead_aes256gcm_ABYTES)
        {
            if (s_isAvailable.Value == 0)
                throw Error.PlatformNotSupported_Algorithm();
            if (!s_selfTest.Value)
                throw Error.Cryptographic_InitializationFailed();
        }

        public static bool IsAvailable => Sodium.TryInitialize() && (s_isAvailable.Value != 0);

        internal override void CreateKey(
            SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            publicKeyBytes = null;
        }

        internal override void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(ciphertext.Length == plaintext.Length + crypto_aead_aes256gcm_ABYTES);

            crypto_aead_aes256gcm_encrypt(
                ref ciphertext.DangerousGetPinnableReference(),
                out ulong ciphertextLength,
                ref plaintext.DangerousGetPinnableReference(),
                (ulong)plaintext.Length,
                ref associatedData.DangerousGetPinnableReference(),
                (ulong)associatedData.Length,
                IntPtr.Zero,
                ref nonce.DangerousGetPinnableReference(),
                keyHandle);

            Debug.Assert((ulong)ciphertext.Length == ciphertextLength);
        }

        internal override int ExportKey(
            SecureMemoryHandle keyHandle,
            KeyBlobFormat format,
            Span<byte> blob)
        {
            Debug.Assert(keyHandle != null);

            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.Export(keyHandle, blob);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.Export(keyHandle, blob);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override int GetDefaultKeySize()
        {
            return crypto_aead_aes256gcm_KEYBYTES;
        }

        internal override int GetKeyBlobSize(
            KeyBlobFormat format)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.BlobSize;
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.BlobSize;
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override ReadOnlySpan<KeyBlobFormat> GetSupportedKeyBlobFormats()
        {
            return s_supportedKeyBlobFormats;
        }

        internal override bool TryDecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> associatedData,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            Debug.Assert(keyHandle != null);
            Debug.Assert(keyHandle.Length == crypto_aead_aes256gcm_KEYBYTES);
            Debug.Assert(nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            Debug.Assert(plaintext.Length == ciphertext.Length - crypto_aead_aes256gcm_ABYTES);

            int error = crypto_aead_aes256gcm_decrypt(
                ref plaintext.DangerousGetPinnableReference(),
                out ulong plaintextLength,
                IntPtr.Zero,
                ref ciphertext.DangerousGetPinnableReference(),
                (ulong)ciphertext.Length,
                ref associatedData.DangerousGetPinnableReference(),
                (ulong)associatedData.Length,
                ref nonce.DangerousGetPinnableReference(),
                keyHandle);

            // libsodium clears the plaintext if decryption fails.

            Debug.Assert(error != 0 || (ulong)plaintext.Length == plaintextLength);
            return error == 0;
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out SecureMemoryHandle keyHandle,
            out byte[] publicKeyBytes)
        {
            switch (format)
            {
            case KeyBlobFormat.RawSymmetricKey:
                return s_rawKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            case KeyBlobFormat.NSecSymmetricKey:
                return s_nsecKeyFormatter.TryImport(blob, out keyHandle, out publicKeyBytes);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryReadAlgorithmIdentifier(
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> nonce)
        {
            bool success = true;
            reader.BeginSequence();
            success &= reader.ObjectIdentifier().SequenceEqual(s_oid.Bytes);
            reader.BeginSequence();
            nonce = reader.OctetString();
            success &= (nonce.Length == crypto_aead_aes256gcm_NPUBBYTES);
            reader.End();
            reader.End();
            success &= reader.Success;
            return success;
        }

        internal override void WriteAlgorithmIdentifier(
            ref Asn1Writer writer,
            ReadOnlySpan<byte> nonce)
        {
            writer.End();
            writer.End();
            writer.OctetString(nonce);
            writer.BeginSequence();
            writer.ObjectIdentifier(s_oid.Bytes);
            writer.BeginSequence();
        }

        private static bool SelfTest()
        {
            return (crypto_aead_aes256gcm_abytes() == (UIntPtr)crypto_aead_aes256gcm_ABYTES)
                && (crypto_aead_aes256gcm_keybytes() == (UIntPtr)crypto_aead_aes256gcm_KEYBYTES)
                && (crypto_aead_aes256gcm_npubbytes() == (UIntPtr)crypto_aead_aes256gcm_NPUBBYTES)
                && (crypto_aead_aes256gcm_nsecbytes() == (UIntPtr)crypto_aead_aes256gcm_NSECBYTES);
        }
    }
}
