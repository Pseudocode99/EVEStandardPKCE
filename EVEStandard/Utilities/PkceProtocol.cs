using System;
using System.Security.Cryptography;
using System.Text;

namespace EVEStandard.Utilities
{
    /// <summary>
    /// In the PCKE protocol, a code challenge is used instead of basic authentication to allow your application to ship without its secret key.
    /// The reason for this being to protect malicious actors from being able to decompile your programs and retrieve the secret key.
    /// A more detailed explanation of the kind of attacks this protects against can be found in RFC 7636
    /// </summary>
    public class PkceProtocol
    {
        /// <summary>
        /// CodeChallenge for the URL
        /// code_challenge=base64url(SHA-256(code verifier))
        /// https://docs.esi.evetech.net/docs/sso/native_sso_flow.html
        /// </summary>
        /// <param name="codeVerifier"></param>
        /// <returns></returns>
        public string GenerateCodeChallenge(string codeVerifier)
        {
            string codeChallenge;
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                codeChallenge = Convert.ToBase64String(challengeBytes)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_');
            }

            return codeChallenge;
        }

        /// <summary>
        /// To create a code challenge your application will first need to create a one time use code verifier.
        /// A simple way to do this is to generate 32 random bytes and base64url encode them. Store this code verifier as you’ll need it in a later step.
        /// To create a corresponding code challenge, SHA-256 hash the code verifier, and then base64url encode the raw hash output.
        /// The base64url encoding is defined in RFC 4648 and should not contain padding.
        /// If you’d like to see an example of creating a code challenge in Python you can find that here.
        /// Feel free to contribute examples in other languages to this repository to help others.
        /// </summary>
        /// <returns></returns>
        public string GenerateCodeVerifier()
        {
            var rng = RandomNumberGenerator.Create();

            var bytes = new byte[32];
            rng.GetBytes(bytes);

            // It is recommended to use a URL-safe string as code_verifier.
            // See section 4 of RFC 7636 for more details.
            var codeVerifier = Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            return codeVerifier;
        }
    }
}