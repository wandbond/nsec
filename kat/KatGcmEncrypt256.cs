using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Kat
{
    // NIST AES-GCM Test Vectors
    // http://csrc.nist.gov/groups/STM/cavp/block-cipher-modes.html
    // gcmEncryptExtIV256.rsp
    public static class KatGcmEncrypt256
    {
        public static readonly TheoryData<string[]> TestVectors = Aes256Gcm.IsAvailable
            ? Utilities.LoadTheoryData(typeof(KatGcmEncrypt256))
            : new TheoryData<string[]> { null };

        [Theory]
        [MemberData(nameof(TestVectors))]
        public static void Test(string[] testVector)
        {
            if (testVector == null)
                return;

            var key = testVector[0];
            var iv = testVector[1];
            var pt = testVector[2];
            var aad = testVector[3];
            var ct = testVector[4];
            var tag = testVector[5];

            var a = new Aes256Gcm();

            using (var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey))
            {
                var n = iv.DecodeHex();
                var p = pt.DecodeHex();
                var d = aad.DecodeHex();

                var expected = (ct + tag).DecodeHex();
                var actual = a.Encrypt(k, n, d, p);

                Assert.Equal(expected, actual);
                Assert.Equal(p, a.Decrypt(k, n, d, expected));
            }
        }
    }
}
