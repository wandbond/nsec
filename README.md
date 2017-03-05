<p align="center">
  <a href="https://nsec.rocks/"><img src="https://cdn.rawgit.com/ektrah/nsec-docs/6e7fd8b0/nsec.svg" width="162" height="148" alt="NSec"></a>
</p>

#

[NSec](https://nsec.rocks/) is a modern and easy-to-use crypto library for
[.NET Core](https://dotnet.github.io/) based on
[libsodium](https://libsodium.org/) &#x2764;.

* **Modern** &ndash; libsodium provides a small set of high-quality, modern
cryptographic primitives, including X25519, Ed25519 and ChaCha20-Poly1305. NSec
wraps these primitives in a modern .NET API based on the new `Span<T>` and
`ReadOnlySpan<T>` types.

* **Easy-to-use** &ndash; NSec wants you to fall into the "pit of success." It
provides a strongly typed data model that represents keys and shared secrets
with specific classes rather than naked byte arrays. This avoids, for example,
accidentally using a key with a wrong algorithm. Still, there are some hard
problems that need to be solved outside of NSec, such as nonce generation and
key management.

* **Secure** &ndash; In addition to the security provided by the cryptographic
primitives, NSec tries to make the use of these primitives secure by default.
For example, all sensitive data such as keys is stored in libsodium's secure
memory rather than on the managed heap and is securely erased when no longer
needed.

* **Fast** &ndash; libsodium is fast, and cryptographic operations in libsodium never
allocate memory on the heap. NSec follows libsodium's lead and avoids
allocations and expensive copies in almost all cases. Only methods that return
byte arrays, keys or shared secrets do allocate memory and should therefore be
kept outside of hot paths.

* **Agile** &ndash; NSec features a simple object model with cryptographic agility in
mind. All algorithms derive from a small set of base classes. This helps writing
code against algorithm interfaces rather than specific algorithms, making it
easy to support multiple algorithms or switch algorithms should the need arise.


## Example

The following C# example shows how to use NSec to sign data with Ed25519 and
verify the signature.

```csharp
// select the Ed25519 signature algorithm
var algorithm = new Ed25519();

// create a new key pair
using (var key = new Key(algorithm))
{
    // generate some data to be signed
    var data = Encoding.UTF8.GetBytes("Use the Force, Luke!");

    // sign the data with the private key
    var signature = algorithm.Sign(key, data);

    // verify the signature and the data with the public key
    algorithm.Verify(key.PublicKey, data, signature);
}
```

## Installation

Soon&trade; (waiting for .NET Core 2.0)


## Documentation

### API Reference

* [Algorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.algorithm)
    * [AeadAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.aeadalgorithm)
    * [HashAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.hashalgorithm)
    * [KeyAgreementAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.keyagreementalgorithm)
    * [KeyDerivationAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.keyderivationalgorithm)
    * [MacAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.macalgorithm)
    * [SignatureAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.signaturealgorithm)
* [Key Class](https://nsec.rocks/docs/api/nsec.cryptography.key)
    * [KeyBlobFormat Enum](https://nsec.rocks/docs/api/nsec.cryptography.keyblobformat)
    * [KeyFlags Enum](https://nsec.rocks/docs/api/nsec.cryptography.keyflags)
* [PublicKey Class](https://nsec.rocks/docs/api/nsec.cryptography.publickey)
* [SecureRandom Class](https://nsec.rocks/docs/api/nsec.cryptography.securerandom)
* [SharedSecret Class](https://nsec.rocks/docs/api/nsec.cryptography.sharedsecret)


## Contributing

NSec is an open source project.
Contributions to the code or documentation are highly welcome.

The easiest way to contribute is by
[submitting a pull request](https://github.com/ektrah/nsec/pulls).
If you've found an problem with NSec, please
[open a new issue](https://github.com/ektrah/nsec/issues).
Feature requests are welcome, too.


## Note

*Cryptography is not magic pixie dust that you can sprinkle on a system to make
it secure.*

NSec aims to provide careful abstractions to make the work with modern
cryptographic primitives relatively easy and pain-free. However, the primitives
are not very useful by themselves and need to be combined into higher-level
security protocols, such as TLS or JSON Web Token. Don't roll your own security
protocols.


## License

NSec is licensed under the [MIT license](LICENSE).
