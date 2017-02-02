using System;
using System.Diagnostics;
using NSec.Cryptography.Formatting;
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
    //      Password Size - Any length.
    //
    //      Salt Size - libsodium uses a length of 32 bytes.
    //
    //      Block Size (r) - libsodium does not allow this parameter to be
    //          specified and always uses a default value of 8.
    //
    //      CPU/Memory Cost (N) - Must be larger than 1, a power of 2, and less
    //          than 2^(128*r/8). libsodium computes this parameter from the
    //          'opslimit' and 'memlimit' arguments.
    //
    //      Parallelization (p) - A positive integer less than or equal to
    //          ((2^32-1)*32)/(128*r). libsodium computes this parameter from
    //          the 'opslimit' and 'memlimit' arguments.
    //
    //      Output Size - A positive integer less than or equal to (2^32-1)*32.
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
            maxStrength: ((UIntPtr.Size * 8 - 1) - 21) * 2 - 1,
            maxOutputSize: int.MaxValue)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal static void PickParameters(
            ulong opslimit,
            UIntPtr memlimit,
            out int N_log2,
            out int p,
            out int r)
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
                maxN = opslimit / ((ulong)r * 4);

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

                p = (int)maxrp / r;
            }
        }

        internal override void PickParameters(
            int strength,
            out ulong opslimit,
            out UIntPtr memlimit)
        {
            Debug.Assert((16 + strength / 2) < (8 * sizeof(ulong) - 1));
            Debug.Assert((21 + strength / 2) < (8 * UIntPtr.Size - 1));

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

        internal override bool TryReadAlgorithmIdentifier(
            ref Asn1Reader reader,
            out ReadOnlySpan<byte> salt,
            out PasswordHashStrength strength)
        {
            bool success = true;
            reader.BeginSequence();
            success &= reader.ObjectIdentifier().SequenceEqual(s_oid.Bytes);
            reader.BeginSequence();
            salt = reader.OctetString();
            success &= (salt.Length == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
            long cost = reader.Integer64();
            int blockSize = reader.Integer32();
            int parallelization = reader.Integer32();
            reader.End();
            reader.End();
            success &= reader.Success;

            // libsodium does not allow passing cost, blockSize and 
            // parallelization directly to the scrypt implementation, so we
            // search for an opslimit and memlimit pair that yields the same
            // values.
            strength = 0;
            if (success)
            {
                for (int i = 6; i <= 24; i += 2)
                {
                    PickParameters(i, out ulong opslimit, out UIntPtr memlimit);
                    PickParameters(opslimit, memlimit, out int N_log2, out int p, out int r);
                    if ((cost == 1L << N_log2) && (blockSize == r) && (parallelization == p))
                    {
                        strength = (PasswordHashStrength)i;
                        return true;
                    }
                }
            }

            return false;
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

        internal override void WriteAlgorithmIdentifier(
            ref Asn1Writer writer,
            ReadOnlySpan<byte> salt,
            PasswordHashStrength strength)
        {
            PickParameters((int)strength, out ulong opslimit, out UIntPtr memlimit);
            PickParameters(opslimit, memlimit, out int N_log2, out int p, out int r);

            writer.End();
            writer.End();
            writer.Integer(p);
            writer.Integer(r);
            writer.Integer(1L << N_log2);
            writer.OctetString(salt);
            writer.BeginSequence();
            writer.ObjectIdentifier(s_oid.Bytes);
            writer.BeginSequence();
        }

        private static bool SelfTest()
        {
            return (crypto_pwhash_scryptsalsa208sha256_saltbytes() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_SALTBYTES)
                && (crypto_pwhash_scryptsalsa208sha256_strbytes() == (UIntPtr)crypto_pwhash_scryptsalsa208sha256_STRBYTES);
        }
    }
}
