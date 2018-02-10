//! Create and parses JWT (JSON Web Tokens)
//!
//! Documentation:  [stable](https://docs.rs/jsonwebtoken/)
#![recursion_limit = "300"]
#![deny(missing_docs)]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde;
extern crate base64;
extern crate ring;
extern crate untrusted;
extern crate chrono;

/// All the errors, generated using error-chain
pub mod errors;
mod header;
mod crypto;
mod serialization;
mod validation;

pub use header::Header;
pub use crypto::{
    Algorithm,
    sign,
    verify,
};
pub use validation::Validation;
pub use serialization::TokenData;


use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use errors::{Result, ErrorKind};
use serialization::{from_jwt_part, from_jwt_part_claims, to_jwt_part};
use validation::{validate};


/// Encode the header and claims given and sign the payload using the algorithm from the header and the key
///
/// ```rust,ignore
/// #[macro_use]
/// extern crate serde_derive;
/// use jsonwebtoken::{encode, Algorithm, Header};
///
/// /// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let my_claims = Claims {
///     sub: "b@b.com".to_owned(),
///     company: "ACME".to_owned()
/// };
///
/// // my_claims is a struct that implements Serialize
/// // This will create a JWT using HS256 as algorithm
/// let token = encode(&Header::default(), &my_claims, "secret".as_ref()).unwrap();
/// ```
pub fn encode<T: Serialize>(header: &Header, claims: &T, key: &[u8]) -> Result<String> {
    let encoded_header = to_jwt_part(&header)?;
    let encoded_claims = to_jwt_part(&claims)?;
    let signing_input = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign(&*signing_input, key.as_ref(), header.alg)?;

    Ok([signing_input, signature].join("."))
}

/// Used in decode: takes the result of a rsplit and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(ErrorKind::InvalidToken.into())
        }
    }}
}

/// Decode a token into a struct containing 2 fields: `claims` and `header`.
///
/// If the token or its signature is invalid or the claims fail validation, it will return an error.
///
/// ```rust,ignore
/// #[macro_use]
/// extern crate serde_derive;
/// use jsonwebtoken::{decode, Validation, Algorithm};
///
/// #[derive(Debug, Serialize, Deserialize)]
/// struct Claims {
///    sub: String,
///    company: String
/// }
///
/// let token = "a.jwt.token".to_string();
/// // Claims is a struct that implements Deserialize
/// let token_data = decode::<Claims>(&token, "secret", &Validation::new(Algorithm::HS256));
/// ```
pub fn decode<T: DeserializeOwned>(token: &str, key: &[u8], validation: &Validation) -> Result<TokenData<T>> {
    let (signature, signing_input) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(signing_input.rsplitn(2, '.'));
    let header: Header = from_jwt_part(header)?;

    if !verify(signature, signing_input, key, header.alg)? {
        return Err(ErrorKind::InvalidSignature.into());
    }

    if !validation.algorithms.contains(&header.alg) {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }

    let (decoded_claims, claims_map): (T, _)  = from_jwt_part_claims(claims)?;

    validate(&claims_map, validation)?;

    Ok(TokenData { header: header, claims: decoded_claims })
}

/// Decode a token and return the Header. This is not doing any kind of validation: it is meant to be
/// used when you don't know which `alg` the token is using and want to find out.
///
/// If the token has an invalid format, it will return an error.
///
/// ```rust,ignore
/// use jsonwebtoken::decode_header;
///
/// let token = "a.jwt.token".to_string();
/// let header = decode_header(&token);
/// ```
pub fn decode_header(token: &str) -> Result<Header> {
    let (_, signing_input) = expect_two!(token.rsplitn(2, '.'));
    let (_, header) = expect_two!(signing_input.rsplitn(2, '.'));
    from_jwt_part(header)
}
