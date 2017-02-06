using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Auto)]
    internal struct Argon2Parameters
    {
        public uint P;
        public uint M;
        public uint T;
    }
}
