using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Kat
{
    // https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2b-kat.txt
    public static class KatBlake2
    {
        public static readonly TheoryData<string, string, string> TestVectors = Utilities.LoadTheoryData3(typeof(KatBlake2));

        [Theory]
        [MemberData(nameof(TestVectors))]
        public static void Test(string msg, string key, string hash)
        {
            var a = new Blake2();

            using (var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey))
            {
                var m = msg.DecodeHex();

                var expected = hash.DecodeHex();
                var actual = a.Hash(k, m, expected.Length);

                Assert.Equal(expected, actual);
            }
        }
    }
}
