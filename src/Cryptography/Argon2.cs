using System;
using System.Diagnostics;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  Argon2i
    //
    //  References
    //
    //      Argon2: the memory-hard function for password hashing and other
    //          applications <https://github.com/P-H-C/phc-winner-argon2/raw/
    //          master/argon2-specs.pdf>
    //
    //      draft-irtf-cfrg-argon2-01 - The memory-hard Argon2 password hash and
    //          proof-of-work function
    //
    //  Parameters
    //
    //      Password Size - Any length from 0 to 2^32-1 bytes.
    //
    //      Salt Size - Any length from 8 to 2^32-1 bytes. 16 bytes is
    //          recommended for password hashing and is the only value allowed
    //          by libsodium.
    //
    //      Degree of Parallelism (p) - Any integer value from 1 to 2**24-1.
    //          libsodium does not allow this parameter to be specified and
    //          always uses a default value of 1.
    //
    //      Memory Size (m) - Any integer number of kibibytes from 8*p to
    //          2^32-1. libsodium allows this parameter to be specified using
    //          the 'memlimit' argument, which is in bytes rather than
    //          kibibytes.
    //
    //      Number of Iterations (t) - Any integer number from 1 to 2^32-1.
    //          libsodium allows this parameter to be specified using
    //          the 'opslimit' argument.
    //
    //      Tag Size - Any integer number of bytes from 4 to 2^32-1. 128 bits
    //          is sufficient for most applications, including key derivation.
    //
    //  Parameter Presets
    //
    //      | Strength         | opslimit | memlimit             | p | m    | t |
    //      | ---------------- | -------- | -------------------- | - | ---- | - |
    //      | Interactive  (6) | 4        | 2^25 bytes  (32 MiB) | 1 | 2^15 | 4 |
    //      | Moderate    (12) | 6        | 2^27 bytes (128 MiB) | 1 | 2^17 | 6 |
    //      | Sensitive   (18) | 8        | 2^29 bytes (512 MiB) | 1 | 2^19 | 8 |
    //
    public sealed class Argon2 : PasswordHashAlgorithm
    {
        private const int ARGON2_MIN_OUTLEN = 16;

        private static readonly int ARGON2_MAX_MEMORY_BITS = Math.Min(32, UIntPtr.Size * 8 - 10 - 1) + 10;

        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Argon2() : base(
            passwordHashSize: crypto_pwhash_argon2i_STRBYTES,
            saltSize: crypto_pwhash_argon2i_SALTBYTES,
            maxStrength: (ARGON2_MAX_MEMORY_BITS - 23) * 3 - 1,
            maxOutputSize: int.MaxValue)
        {
            if (!s_selfTest.Value)
                throw new InvalidOperationException();
        }

        internal override void PickParameters(
            int strength,
            out ulong opslimit,
            out UIntPtr memlimit)
        {
            Debug.Assert((23 + strength / 3) < ARGON2_MAX_MEMORY_BITS);

            opslimit = (ulong)(2 + strength / 3);              //  4, 6 or 8
            memlimit = (UIntPtr)(1UL << (23 + strength / 3));  //  2^25, 2^27 or 2^29
        }

        internal override bool TryDeriveBytesCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ulong opslimit,
            UIntPtr memlimit,
            Span<byte> bytes)
        {
            Debug.Assert(salt.Length == crypto_pwhash_argon2i_SALTBYTES);
            Debug.Assert(!bytes.IsEmpty);

            int error;

            if (bytes.Length >= ARGON2_MIN_OUTLEN)
            {
                error = crypto_pwhash_argon2i(
                    ref bytes.DangerousGetPinnableReference(),
                    (ulong)bytes.Length,
                    ref password.DangerousGetPinnableReference(),
                    (ulong)password.Length,
                    ref salt.DangerousGetPinnableReference(),
                    opslimit,
                    memlimit,
                    crypto_pwhash_argon2i_ALG_ARGON2I13);
            }
            else
            {
                Span<byte> temp;
                try
                {
                    unsafe
                    {
                        byte* pointer = stackalloc byte[ARGON2_MIN_OUTLEN];
                        temp = new Span<byte>(pointer, ARGON2_MIN_OUTLEN);
                    }

                    error = crypto_pwhash_argon2i(
                        ref temp.DangerousGetPinnableReference(),
                        (ulong)temp.Length,
                        ref password.DangerousGetPinnableReference(),
                        (ulong)password.Length,
                        ref salt.DangerousGetPinnableReference(),
                        opslimit,
                        memlimit,
                        crypto_pwhash_argon2i_ALG_ARGON2I13);

                    temp.Slice(0, bytes.Length).CopyTo(bytes);
                }
                finally
                {
                    sodium_memzero(ref temp.DangerousGetPinnableReference(), (UIntPtr)temp.Length);
                }
            }

            return error == 0;
        }

        internal override bool TryHashPasswordCore(
            ReadOnlySpan<byte> password,
            ulong opslimit,
            UIntPtr memlimit,
            Span<sbyte> passwordHash)
        {
            Debug.Assert(passwordHash.Length == crypto_pwhash_argon2i_STRBYTES);

            int error = crypto_pwhash_argon2i_str(
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
            Debug.Assert(passwordHash.Length == crypto_pwhash_argon2i_STRBYTES);

            int error = crypto_pwhash_argon2i_str_verify(
                ref passwordHash.DangerousGetPinnableReference(),
                ref password.DangerousGetPinnableReference(),
                (ulong)password.Length);

            return error == 0;
        }

        private static bool SelfTest()
        {
            return (crypto_pwhash_argon2i_alg_argon2i13() == crypto_pwhash_argon2i_ALG_ARGON2I13)
                && (crypto_pwhash_argon2i_saltbytes() == (UIntPtr)crypto_pwhash_argon2i_SALTBYTES)
                && (crypto_pwhash_argon2i_strbytes() == (UIntPtr)crypto_pwhash_argon2i_STRBYTES);
        }
    }
}
