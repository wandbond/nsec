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
    //      TODO
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
        private static readonly Lazy<bool> s_selfTest = new Lazy<bool>(new Func<bool>(SelfTest));

        public Argon2() : base(
            passwordHashSize: crypto_pwhash_argon2i_STRBYTES,
            saltSize: crypto_pwhash_argon2i_SALTBYTES,
            maxStrength: ((UIntPtr.Size * 8 - 1) - 23) * 3 - 1,
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
            Debug.Assert((23 + strength / 3) < (8 * UIntPtr.Size - 1));

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

            int error = crypto_pwhash_argon2i(
                ref bytes.DangerousGetPinnableReference(),
                (ulong)bytes.Length,
                ref password.DangerousGetPinnableReference(),
                (ulong)password.Length,
                ref salt.DangerousGetPinnableReference(),
                opslimit,
                memlimit,
                crypto_pwhash_argon2i_ALG_ARGON2I13);

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
