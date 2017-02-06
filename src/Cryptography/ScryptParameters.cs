using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Auto)]
    internal struct ScryptParameters
    {
        public ulong N;
        public uint R;
        public uint P;
    }
}
