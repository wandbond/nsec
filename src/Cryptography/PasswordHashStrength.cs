namespace NSec.Cryptography
{
    // The actual strength parameters are specific to the algorithms. So, if
    // callers have a PasswordHashAlgorithm instance, they would need to check
    // if it's scrypt or Argon2i to pass suitable parameters. The Password-
    // HashStrength enum defines values that roughly provide the same strengths
    // for both algorithms. This solves the problem, but does not allow fine-
    // tuned parameter selection.
    public enum PasswordHashStrength
    {
        Interactive = 6,
        Moderate = 12,
        Sensitive = 18,
    }
}
