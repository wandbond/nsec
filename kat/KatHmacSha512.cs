using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Kat
{
    // NIST HMAC-SHA-2 Test Vectors
    // http://csrc.nist.gov/groups/STM/cavp/message-authentication.html
    // HMAC.rsp
    public static class KatHmacSha512
    {
        public static readonly TheoryData<string, string, string> TestVectors = Utilities.LoadTheoryData3(typeof(KatHmacSha512));

        [Theory]
        [MemberData(nameof(TestVectors))]
        public static void Test(string key, string msg, string mac)
        {
            var a = new HmacSha512();

            using (var k = Key.Import(a, key.DecodeHex(), KeyBlobFormat.RawSymmetricKey))
            {
                var m = msg.DecodeHex();

                var expected = mac.DecodeHex();
                var actual = a.Sign(k, m, expected.Length);

                Assert.Equal(expected, actual);
                Assert.True(a.TryVerify(k, m, expected));
            }
        }
    }
}
