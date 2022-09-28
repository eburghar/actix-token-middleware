use awc::error::SendRequestError;
use jsonwebtoken as jwt;
use std::str::Utf8Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Failed to get JKWS from endpoint: {0}")]
	GetError(#[source] SendRequestError),
	#[error("Failed to get JKWS response body")]
	BodyResponse,
	#[error("Failed to decode JKWS response body: {0}")]
	DecodeError(#[source] Utf8Error),
	#[error("Failed to deserialize JKWS: {0}")]
	DeserError(#[source] serde_json::Error),
	#[error("Token error: {0}")]
	JwtError(#[source] jwt::errors::Error),
	#[error("Token header error: {0}")]
	JwtHeaderError(#[source] jwt::errors::Error),
	#[error("kid attibute must be specified in the jwt header")]
	NoKid,
	#[error("Unknown key id {0}")]
	KeyNotFound(String),
	#[error("Claim {0} is not in the token")]
	ClaimNotFound(String),
	#[error("Expected claim {0} == {1} but found {2}")]
	Claim(String, String, String),
}
