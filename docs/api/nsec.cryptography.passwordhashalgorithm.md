# PasswordHashAlgorithm Class

Represents a password hashing algorithm.

    public abstract class PasswordHashAlgorithm : Algorithm


## Inheritance Hierarchy

* [[Algorithm|Algorithm Class]]
    * **PasswordHashAlgorithm**
        * Argon2
        * Scrypt


## [TOC] Summary


## Properties


### MaxOutputSize

Gets the maximum size, in bytes, of the password hashing output.

    public int MaxOutputSize { get; }

#### Property value

The maximum size, in bytes, of the password hashing output.


### SaltSize

Gets the salt size, in bytes.

    public bool SaltSize { get; }

#### Property value

The salt size, in bytes.


## Methods


### DeriveBytes(string, ReadOnlySpan<byte>, PasswordHashStrength, int)

Derives the specified number of bytes from a password.

    public byte[] DeriveBytes(
        string password,
        ReadOnlySpan<byte> salt,
        PasswordHashStrength strength,
        int count)

#### Parameters

password
: The password to derive bytes from.

salt
: A salt of length [[SaltSize|PasswordHashAlgorithm Class#SaltSize]].

strength
: A [[PasswordHashStrength|PasswordHashStrength Enum]] value that specifies the
    strength of the password hashing operation.

count
: The number of bytes to derive.

#### Return value

An array of bytes that contains the derived bytes.

#### Exceptions

ArgumentNullException
: `password` is `null`.

ArgumentException
: `salt.Length` is not equal to
    [[SaltSize|PasswordHashAlgorithm Class#SaltSize]].

ArgumentOutOfRangeException
: `strength` is out of range.

ArgumentOutOfRangeException
: `count` is less than 0 or greater than 
    [[MaxOutputSize|PasswordHashAlgorithm Class#MaxOutputSize]].


### DeriveBytes(string, ReadOnlySpan<byte>, PasswordHashStrength, Span<byte>)

Fills the specified span of bytes with bytes derived from a password.

    public void DeriveBytes(
        string password,
        ReadOnlySpan<byte> salt,
        PasswordHashStrength strength,
        Span<byte> bytes)

#### Parameters

password
: The password to derive bytes from.

salt
: A salt of length [[SaltSize|PasswordHashAlgorithm Class#SaltSize]].

strength
: A [[PasswordHashStrength|PasswordHashStrength Enum]] value that specifies the
    strength of the password hashing operation.

bytes
: The span to fill with bytes derived from the shared secret.

#### Exceptions

ArgumentNullException
: `password` is `null`.

ArgumentException
: `salt.Length` is not equal to
    [[SaltSize|PasswordHashAlgorithm Class#SaltSize]].

ArgumentOutOfRangeException
: `strength` is out of range.

ArgumentException
: `bytes.Length` is greater than
    [[MaxOutputSize|PasswordHashAlgorithm Class#MaxOutputSize]].


### DeriveKey(string, ReadOnlySpan<byte>, PasswordHashStrength, Algorithm, KeyFlags)

Derives a key for the specified algorithm from a password.

    public Key DeriveKey(
        string password,
        ReadOnlySpan<byte> salt,
        PasswordHashStrength strength,
        Algorithm algorithm,
        KeyFlags flags = KeyFlags.None)

#### Parameters

password
: The password to derive a key from.

salt
: A salt of length [[SaltSize|PasswordHashAlgorithm Class#SaltSize]].

strength
: A [[PasswordHashStrength|PasswordHashStrength Enum]] value that specifies the
    strength of the password hashing operation.

algorithm
: The algorithm for the new key.

flags
: A bitwise combination of [[KeyFlags|KeyFlags Enum]] values that specifies
    the flags for the new key.

#### Return value

A new instance of the [[Key|Key Class]] class that represents the derived key.

#### Exceptions

ArgumentNullException
: `password` or `algorithm` is `null`.

ArgumentException
: `salt.Length` is not equal to
    [[SaltSize|PasswordHashAlgorithm Class#SaltSize]].

ArgumentOutOfRangeException
: `strength` is out of range.

NotSupportedException
: The specified algorithm does not support key derivation.


### Hash(string, PasswordHashStrength)

Computes a hash for the specified password.

    public string Hash(
        string password,
        PasswordHashStrength strength)

#### Parameters

password
: The password to hash.

strength
: A [[PasswordHashStrength|PasswordHashStrength Enum]] value that specifies the
    strength of the password hashing operation.

#### Return value

The computed hash.

#### Exceptions

ArgumentNullException
: `password` or `algorithm` is `null`.

ArgumentOutOfRangeException
: `strength` is out of range.

CryptographicException
: The computation didn't complete, usually because the operating system refused
    to allocate the amount of requested memory.


### TryVerify(string, string)

Attempts to verify the specified password using the specified password hash.

    public bool TryVerify(
        string password,
        string passwordHash)

#### Parameters

password
: The password to be verified.

passwordHash
: The password hash to be verified.

#### Return value

`true` if verification succeeds; otherwise, `false`.

#### Exceptions

ArgumentNullException
: `password` or `passwordHash` is `null`.


### Verify(string, string)

Verifies the specified password using the specified password hash.

    public void Verify(
        string password,
        string passwordHash)

#### Parameters

password
: The password to be verified.

passwordHash
: The password hash to be verified.

#### Exceptions

ArgumentNullException
: `password` or `passwordHash` is `null`.

FormatException
: `passwordHash` has an invalid format.

CryptographicException
: Verification failed.


## See also

* API Reference
    * [[Algorithm Class]]
    * [[PasswordHashStrength Enum]]
