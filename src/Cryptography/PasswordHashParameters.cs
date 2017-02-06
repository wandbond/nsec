using System.Runtime.InteropServices;

namespace NSec.Cryptography
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct PasswordHashParameters
    {
        [FieldOffset(0)]
        public PasswordHashAlgorithm Algorithm;
        [FieldOffset(8)]
        public Argon2Parameters Argon2Parameters;
        [FieldOffset(8)]
        public ScryptParameters ScryptParameters;
    }
}
