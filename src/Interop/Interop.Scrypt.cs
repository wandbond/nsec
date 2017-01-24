using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;
        internal const int crypto_pwhash_scryptsalsa208sha256_STRBYTES = 102;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256(
            ref byte @out,
            ulong outlen,
            ref byte passwd,
            ulong passwdlen,
            ref byte salt,
            ulong opslimit,
            UIntPtr memlimit);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_saltbytes();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str(
            ref sbyte @out,
            ref byte passwd,
            ulong passwdlen,
            ulong opslimit,
            UIntPtr memlimit);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_str_verify(
            ref sbyte str,
            ref byte passwd,
            ulong passwdlen);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern UIntPtr crypto_pwhash_scryptsalsa208sha256_strbytes();
    }
}
