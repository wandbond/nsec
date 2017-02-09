using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Kat
{
    // NIST AES-GCM Test Vectors
    // http://csrc.nist.gov/groups/STM/cavp/block-cipher-modes.html
    // gcmDecrypt256.rsp
    public static class KatGcmDecrypt256
    {
        public static readonly TheoryData<string[]> TestVectors = Utilities.LoadTheoryData(typeof(KatGcmDecrypt256));

        [Theory]
        [MemberData(nameof(TestVectors))]
        public static void Test(string[] testVector)
        {
            if (!Aes256Gcm.IsAvailable)
                return;

            var key = testVector[0];
            var iv = testVector[1];
            var ct = testVector[2];
            var aad = testVector[3];
            var tag = testVector[4];
            var pt = testVector[5];
            var fail = bool.Parse(testVector[6]);

            var a = new Aes256Gcm();

            using (var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey))
            {
                var n = iv.DecodeHex();
                var c = (ct + tag).DecodeHex();
                var d = aad.DecodeHex();

                var expected = pt.DecodeHex();
                var actual = new byte[c.Length - a.TagSize];

                if (fail)
                {
                    Assert.False(a.TryDecrypt(k, n, d, c, actual));
                }
                else
                {
                    Assert.True(a.TryDecrypt(k, n, d, c, actual));
                    Assert.Equal(expected, actual);
                }
            }
        }
    }
}
