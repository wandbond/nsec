using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Kat
{
    // https://ed25519.cr.yp.to/python/sign.input
    public static class KatEd25519
    {
        public static readonly TheoryData<string, string, string, string> TestVectors = Utilities.LoadTheoryData4(typeof(KatEd25519));

        [Theory]
        [MemberData(nameof(TestVectors))]
        public static void Test(string sk, string pk, string msg, string sig)
        {
            var a = new Ed25519();

            using (var k = Key.Import(a, sk.DecodeHex().Substring(0, 32), KeyBlobFormat.RawPrivateKey))
            {
                var p = PublicKey.Import(a, pk.DecodeHex(), KeyBlobFormat.RawPublicKey);
                var m = msg.DecodeHex();

                var expected = sig.DecodeHex().Substring(0, a.SignatureSize);
                var actual = a.Sign(k, m);

                Assert.Equal(expected, actual);
                Assert.True(a.TryVerify(p, m, expected));
            }
        }
    }
}
