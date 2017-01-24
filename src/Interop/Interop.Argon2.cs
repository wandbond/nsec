using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_argon2i_ALG_ARGON2I13 = 1;
        internal const int crypto_pwhash_argon2i_SALTBYTES = 16;
        internal const int crypto_pwhash_argon2i_STRBYTES = 128;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_argon2i(
            ref byte @out,
            ulong outlen,
            ref byte passwd,
            ulong passwdlen,
            ref byte salt,
            ulong opslimit,
            UIntPtr memlimit,
            int alg);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_argon2i_alg_argon2i13();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_saltbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_argon2i_str(
            ref sbyte @out,
            ref byte passwd,
            ulong passwdlen,
            ulong opslimit,
            UIntPtr memlimit);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_argon2i_str_verify(
            ref sbyte str,
            ref byte passwd,
            ulong passwdlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_argon2i_strbytes();
    }
}
