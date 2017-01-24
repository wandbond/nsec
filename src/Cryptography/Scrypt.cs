using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  scrypt
    //
    //  References
    //
    //      RFC 7914 - The scrypt Password-Based Key Derivation Function
    //
    //  Parameters
    //
    //      TODO
    //
    //  Parameter Presets
    //
    //      | Strength         | opslimit | memlimit              | N    | r | p |
    //      | ---------------- | -------- | --------------------- | ---- | - | - |
    //      | Interactive  (6) | 2^19     | 2^24 bytes   (16 MiB) | 2^14 | 8 | 1 |
    //      | Moderate    (12) | 2^22     | 2^27 bytes  (128 MiB) | 2^17 | 8 | 1 |
    //      | Sensitive   (18) | 2^25     | 2^30 bytes (1024 MiB) | 2^20 | 8 | 1 |
    //
    public sealed class Scrypt : PasswordHashAlgorithm
    {
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        private static readonly Oid s_oid = new Oid(1, 3, 6, 1, 4, 1, 11591, 4, 11);

        public Scrypt() : base(
            passwordHashSize: crypto_pwhash_scryptsalsa208sha256_STRBYTES,
            saltSize: crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
            maxStrength: (UIntPtr.Size * 8 - 21) * 2 - 1,
            minOutputSize: 0,
            maxOutputSize: int.MaxValue)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal static void PickParameters(
            ulong opslimit,
            UIntPtr memlimit,
            out int N_log2,
            out uint p,
            out uint r)
        {
            ulong maxN;
            ulong maxrp;

            if (opslimit < 32768)
            {
                opslimit = 32768;
            }

            r = 8;

            if (opslimit < (ulong)memlimit / 32)
            {
                p = 1;
                maxN = opslimit / (r * 4);

                for (N_log2 = 1; N_log2 < 63; N_log2 += 1)
                {
                    if ((1UL << N_log2) > maxN / 2)
                    {
                        break;
                    }
                }
            }
            else
            {
                maxN = (ulong)memlimit / ((ulong)r * 128);

                for (N_log2 = 1; N_log2 < 63; N_log2 += 1)
                {
                    if ((1UL << N_log2) > maxN / 2)
                    {
                        break;
                    }
                }

                maxrp = (opslimit / 4) / (1UL << N_log2);

                if (maxrp > 0x3fffffff)
                {
                    maxrp = 0x3fffffff;
                }

                p = (uint)maxrp / r;
            }
        }

        internal override void PickParameters(
            int strength,
            out ulong opslimit,
            out UIntPtr memlimit)
        {
            Debug.Assert(strength <= 86);

            opslimit = 1UL << (16 + strength / 2);             //  2^19, 2^22 or 2^25
            memlimit = (UIntPtr)(1UL << (21 + strength / 2));  //  2^24, 2^27 or 2^30
        }

        internal override bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ulong opslimit,
            UIntPtr memlimit,
            Span<byte> bytes)
        {
            Debug.Assert(salt.Length == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

            int error = crypto_pwhash_scryptsalsa208sha256(
                ref bytes.DangerousGetPinnableReference(),
                (ulong)bytes.Length,
                ref password.DangerousGetPinnableReference(),
                (ulong)password.Length,
                ref salt.DangerousGetPinnableReference(),
                opslimit,
                memlimit);

            return error == 0;
        }

        internal override bool TryHashPasswordCore(
            ReadOnlySpan<byte> password,
            ulong opslimit,
            UIntPtr memlimit,
            Span<sbyte> passwordHash)
        {
            Debug.Assert(passwordHash.Length == crypto_pwhash_scryptsalsa208sha256_STRBYTES);

            int error = crypto_pwhash_scryptsalsa208sha256_str(
                ref passwordHash.DangerousGetPinnableReference(),
                ref password.DangerousGetPinnableReference(),
                (ulong)password.Length,
                opslimit,
                memlimit);

            return error == 0;
        }

        internal override bool TryVerifyPasswordCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<sbyte> passwordHash)
        {
            Debug.Assert(passwordHash.Length == crypto_pwhash_scryptsalsa208sha256_STRBYTES);

            int error = crypto_pwhash_scryptsalsa208sha256_str_verify(
                ref passwordHash.DangerousGetPinnableReference(),
                ref password.DangerousGetPinnableReference(),
                (ulong)password.Length);

            return error == 0;
        }

        private static bool SelfTest()
        {
            return (crypto_pwhash_scryptsalsa208sha256_saltbytes() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_SALTBYTES)
                && (crypto_pwhash_scryptsalsa208sha256_strbytes() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_STRBYTES);
        }
    }
}
