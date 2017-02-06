using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_pwhash_scryptsalsa208sha256_SALTBYTES = 32;
        internal const int crypto_pwhash_scryptsalsa208sha256_STRBYTES = 102;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_pwhash_scryptsalsa208sha256_ll(
            ref byte passwd,
            UIntPtr passwdlen,
            ref byte salt,
            UIntPtr saltlen,
            ulong N,
            uint r,
            uint p,
            ref byte buf,
            UIntPtr buflen);

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
