use base64;
use serde_json;
use ring;

error_chain! {
    errors {
        /// When a token doesn't have a valid JWT shape
        InvalidToken {
            description("invalid token")
            display("Invalid token")
        }
        /// When the signature doesn't match
        InvalidSignature {
            description("invalid signature")
            display("Invalid signature")
        }
        /// When the secret given is not a valid RSA key
        InvalidKey {
            description("invalid key")
            display("Invalid Key")
        }

        // Validation error

        /// When a token’s `exp` claim indicates that it has expired
        ExpiredSignature {
            description("expired signature")
            display("Expired Signature")
        }
        /// When a token’s `iss` claim does not match the expected issuer
        InvalidIssuer {
            description("invalid issuer")
            display("Invalid Issuer")
        }
        /// When a token’s `aud` claim does not match one of the expected audience values
        InvalidAudience {
            description("invalid audience")
            display("Invalid Audience")
        }
        /// When a token’s `aud` claim does not match one of the expected audience values
        InvalidSubject {
            description("invalid subject")
            display("Invalid Subject")
        }
        /// When a token’s `iat` claim is in the future
        InvalidIssuedAt {
            description("invalid issued at")
            display("Invalid Issued At")
        }
        /// When a token’s nbf claim represents a time in the future
        ImmatureSignature {
            description("immature signature")
            display("Immature Signature")
        }
        /// When the algorithm in the header doesn't match the one passed to `decode`
        InvalidAlgorithm {
            description("Invalid algorithm")
            display("Invalid Algorithm")
        }
    }

    foreign_links {
        Unspecified(ring::error::Unspecified) #[doc = "An error happened while signing/verifying a token with RSA"];
        Base64(base64::DecodeError) #[doc = "An error happened while decoding some base64 text"];
        Json(serde_json::Error) #[doc = "An error happened while serializing/deserializing JSON"];
        Utf8(::std::string::FromUtf8Error) #[doc = "An error happened while trying to convert the result of base64 decoding to a String"];
    }
}
