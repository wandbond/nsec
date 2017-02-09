using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Kat
{
    // NIST SHA Test Vectors
    // http://csrc.nist.gov/groups/STM/cavp/secure-hashing.html
    // SHAKE256ShortMsg.rsp
    public static class KatShake256Short
    {
        public static readonly TheoryData<string, string> TestVectors = Utilities.LoadTheoryData2(typeof(KatShake256Short));

        [Theory]
        [MemberData(nameof(TestVectors))]
        public static void Test(string msg, string digest)
        {
            var a = new Shake256();

            var m = msg.DecodeHex();

            var expected = digest.DecodeHex();
            var actual = a.Hash(m, expected.Length);

            Assert.Equal(expected, actual);
        }
    }
}
