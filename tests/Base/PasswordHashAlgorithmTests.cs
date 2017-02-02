using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Base
{
    public static class PasswordHashAlgorithmTests
    {
        public static readonly TheoryData<Type> PasswordHashAlgorithms = new TheoryData<Type> // TODO: move to registry
        {
            typeof(Argon2),
            typeof(Scrypt),
        };

        private const string s_password = "Passw0rd!";

        #region Properties

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void Properties(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.True(a.SaltSize > 0);
        }

        #endregion

        #region DeriveBytes #1

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithNullPassword(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("password", () => a.DeriveBytes(null, ReadOnlySpan<byte>.Empty, 0, 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSaltTooShort(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, new byte[a.SaltSize - 1], 0, 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSaltTooLarge(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, new byte[a.SaltSize + 1], 0, 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithZeroStrength(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentOutOfRangeException>("strength", () => a.DeriveBytes(s_password, new byte[a.SaltSize], 0, 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithNegativeCount(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, -1));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithZeroCount(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            var b = a.DeriveBytes(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, 0);
            Assert.NotNull(b);
            Assert.Equal(0, b.Length);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSmallCount(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            var b = a.DeriveBytes(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, 3);
            Assert.NotNull(b);
            Assert.Equal(3, b.Length);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesSuccess(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            var b = a.DeriveBytes(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, 32);
            Assert.NotNull(b);
            Assert.Equal(32, b.Length);
        }

        #endregion

        #region DeriveBytes #2

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithNullPassword(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("password", () => a.DeriveBytes(null, ReadOnlySpan<byte>.Empty, 0, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSaltTooShort(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, new byte[a.SaltSize - 1], 0, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSaltTooLarge(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("salt", () => a.DeriveBytes(s_password, new byte[a.SaltSize + 1], 0, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithZeroStrength(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentOutOfRangeException>("strength", () => a.DeriveBytes(s_password, new byte[a.SaltSize], 0, Span<byte>.Empty));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithNegativeCount(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentOutOfRangeException>("count", () => a.DeriveBytes(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, -1));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithZeroCount(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            a.DeriveBytes(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, new byte[0]);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanWithSmallCount(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            a.DeriveBytes(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, new byte[3]);
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveBytesWithSpanSuccess(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            a.DeriveBytes(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, new byte[32]);
        }

        #endregion

        #region DeriveKey

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithNullPassword(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("password", () => a.DeriveKey(null, ReadOnlySpan<byte>.Empty, 0, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithSaltTooShort(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s_password, new byte[a.SaltSize - 1], 0, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithSaltTooLarge(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentException>("salt", () => a.DeriveKey(s_password, new byte[a.SaltSize + 1], 0, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithZeroStrength(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentOutOfRangeException>("strength", () => a.DeriveKey(s_password, new byte[a.SaltSize], 0, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeyWithNullAlgorithm(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("algorithm", () => a.DeriveKey(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void DeriveKeySuccess(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);
            var x = new ChaCha20Poly1305();

            using (var k = a.DeriveKey(s_password, new byte[a.SaltSize], PasswordHashStrength.Interactive, x))
            {
                Assert.NotNull(k);
                Assert.Same(x, k.Algorithm);
            }
        }

        #endregion

        #region HashPassword

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void HashPasswordWithNullPassword(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("password", () => a.HashPassword(null, 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void HashPasswordWithZeroStrength(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentOutOfRangeException>("strength", () => a.HashPassword(s_password, 0));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void HashPasswordSuccess(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.NotNull(a.HashPassword(s_password, PasswordHashStrength.Interactive));
        }

        #endregion

        #region TryVerifyPassword

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void TryVerifyPasswordWithNullPassword(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("password", () => a.TryVerifyPassword(null, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void TryVerifyPasswordWithNullPasswordHash(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("passwordHash", () => a.TryVerifyPassword(s_password, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void TryVerifyPasswordWithEmbeddedNullPasswordHash(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.False(a.TryVerifyPassword(s_password, "abc\0abc"));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void TryVerifyPasswordWithNonAsciiPasswordHash(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.False(a.TryVerifyPassword(s_password, "\u3053\u3093\u306b\u3061\u306f"));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void TryVerifyPasswordWithPasswordHashTooLong(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.False(a.TryVerifyPassword(s_password, new string(' ', 130)));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void TryVerifyPasswordSuccess(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            var b = a.HashPassword(s_password, PasswordHashStrength.Interactive);

            Assert.True(a.TryVerifyPassword(s_password, b));
        }

        #endregion

        #region VerifyPassword

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void VerifyPasswordWithNullPassword(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("password", () => a.VerifyPassword(null, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void VerifyPasswordWithNullPasswordHash(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<ArgumentNullException>("passwordHash", () => a.VerifyPassword(s_password, null));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void VerifyPasswordWithEmbeddedNullPasswordHash(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<FormatException>(() => a.VerifyPassword(s_password, "abc\0abc"));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void VerifyPasswordWithNonAsciiPasswordHash(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<FormatException>(() => a.VerifyPassword(s_password, "\u3053\u3093\u306b\u3061\u306f"));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void VerifyPasswordWithPasswordHashTooLong(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            Assert.Throws<FormatException>(() => a.VerifyPassword(s_password, new string(' ', 130)));
        }

        [Theory]
        [MemberData(nameof(PasswordHashAlgorithms))]
        public static void VerifyPasswordSuccess(Type algorithmType)
        {
            var a = (PasswordHashAlgorithm)Activator.CreateInstance(algorithmType);

            var b = a.HashPassword(s_password, PasswordHashStrength.Interactive);

            a.VerifyPassword(s_password, b);
        }

        #endregion
    }
}
