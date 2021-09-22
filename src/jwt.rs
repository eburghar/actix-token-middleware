use actix_web::client::{Client, SendRequestError};
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::{
	convert::TryFrom,
	ops::Deref,
	result,
	str::{from_utf8, Utf8Error},
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize, Clone)]
pub struct Jwks {
	keys: Vec<jwk::JsonWebKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Failed to get JKWS from endpoint")]
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

#[derive(Clone)]
pub struct Claims(BTreeMap<String, String>);

impl Deref for Claims {
	type Target = BTreeMap<String, String>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl Claims {
	pub fn new(map: BTreeMap<String, String>) -> Self {
		Self(map)
	}

	pub fn check(&self, tokendata: &jwt::TokenData<Value>) -> Result<()> {
		for valid in self.0.iter().map(|(key, val)| {
			tokendata
				.claims
				.get(key)
				.ok_or_else(|| Error::ClaimNotFound(key.to_owned()))
				.and_then(|tok_val| {
					(tok_val == val).then(|| true).ok_or_else(|| {
						Error::Claim(key.to_owned(), val.to_string(), tok_val.to_string())
					})
				})
		}) {
			let _ = valid?;
		}
		Ok(())
	}
}

impl TryFrom<&str> for Claims {
	type Error = Error;

	fn try_from(input: &str) -> result::Result<Self, Self::Error> {
		let map = serde_json::from_str::<BTreeMap<String, String>>(input)
			.map_err(|e| Error::DeserError(e))?;
		Ok(Self(map))
	}
}

impl Jwks {
	/// Initialize a Jwks from a url
	pub async fn get(url: &str) -> Result<Self> {
		let client = Client::default();
		let mut response = client
			.get(url)
			.send()
			.await
			.map_err(|e| Error::GetError(e))?;
		let body = response.body().await.map_err(|_| Error::BodyResponse)?;
		from_utf8(&body)
			.map_err(|e| Error::DecodeError(e))
			.and_then(|s| serde_json::from_str::<Jwks>(s).map_err(|e| Error::DeserError(e)))
	}

	/// Return the JsonWebKey corresponding to the given kid
	fn get_key(&self, kid: &str) -> Option<&jwk::JsonWebKey> {
		self.keys
			.iter()
			.find(|k| k.key_id.as_ref().filter(|id| *id == kid).is_some())
	}

	/// check the jwt
	pub fn check_jwt(&self, jwt: &str) -> Result<jwt::TokenData<Value>> {
		let header = jwt::decode_header(&jwt).map_err(|e| Error::JwtHeaderError(e))?;
		let kid = header.kid.ok_or_else(|| Error::NoKid)?;
		let key = self
			.get_key(&kid)
			.ok_or_else(|| Error::KeyNotFound(kid.to_owned()))?;
		// prefer the key alg to the jwt alg
		let alg: jwt::Algorithm = key.algorithm.unwrap().into();
		let validation = jwt::Validation {
			// validate_exp: false,
			algorithms: vec![alg],
			..Default::default()
		};
		jwt::decode::<Value>(&jwt, &key.key.to_decoding_key(), &validation)
			.map_err(|e| Error::JwtError(e))
	}

	/// ensure that all claims are present in the token with correct values
	pub fn validate_jwt(&self, jwt: &str, claims: &BTreeMap<String, String>) -> Result<()> {
		let tokendata = self.check_jwt(jwt)?;
		for valid in claims.iter().map(|(key, val)| {
			tokendata
				.claims
				.get(key)
				.ok_or_else(|| Error::ClaimNotFound(key.to_owned()))
				.and_then(|tok_val| {
					(tok_val == val).then(|| true).ok_or_else(|| {
						Error::Claim(key.to_owned(), val.to_string(), tok_val.to_string())
					})
				})
		}) {
			let _ = valid?;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use actix_rt;

	#[actix_rt::test]
	async fn jkws_not_empty() {
		let url = "https://git.itsufficient.me/-/jwks";
		let jwks = Jwks::get(&url).await.unwrap();
		assert_eq!(jwks.keys.is_empty(), false);
	}

	#[actix_rt::test]
	async fn kid_found() {
		let url = "https://git.itsufficient.me/-/jwks";
		let jwks = Jwks::get(&url).await.unwrap();
		assert_eq!(
			jwks.get_key("MnX6_VzIPaLxufWSUXvwbmzD3GhHSc_y-SvVmI_q0Rw")
				.is_some(),
			true
		);
	}

	#[actix_rt::test]
	async fn check_jwt() {
		let url = "https://git.itsufficient.me/-/jwks";
		let jwks = Jwks::get(&url).await.unwrap();
		let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1uWDZfVnpJUGFMeHVmV1NVWHZ3Ym16RDNHaEhTY195LVN2Vm1JX3EwUnciLCJ0eXAiOiJKV1QifQ.eyJuYW1lc3BhY2VfaWQiOiI4IiwibmFtZXNwYWNlX3BhdGgiOiJhbHBpbmUiLCJwcm9qZWN0X2lkIjoiOTciLCJwcm9qZWN0X3BhdGgiOiJhbHBpbmUvc3RhdGljc2VydmUiLCJ1c2VyX2lkIjoiMiIsInVzZXJfbG9naW4iOiJlcmljIiwidXNlcl9lbWFpbCI6ImVyaWMuYnVyZ2hhcmRAaXRzdWZmaWNpZW50Lm1lIiwicGlwZWxpbmVfaWQiOiI2NDUiLCJwaXBlbGluZV9zb3VyY2UiOiJwdXNoIiwiam9iX2lkIjoiOTM3IiwicmVmIjoiMC4xLjEiLCJyZWZfdHlwZSI6InRhZyIsInJlZl9wcm90ZWN0ZWQiOiJ0cnVlIiwianRpIjoiMjRkYzU3MDItMGRlMi00MDNhLWFkNzYtOTExZDA0YzhkODc3IiwiaXNzIjoiZ2l0Lml0c3VmZmljaWVudC5tZSIsImlhdCI6MTYzMTg4MjE3MywibmJmIjoxNjMxODgyMTY4LCJleHAiOjE2MzE4ODU3NzMsInN1YiI6ImpvYl85MzcifQ.zCv3W2S9nrMeFEEERuSqa6TzolrQPSw-bXYiVGAzPJXtdEGiDwoLtNRpISrWe4gGZicKA5RgzrW13IrlOxZqIayhKITZo48B_sWYswk7pqcNaWReTrpaKR0mQcR44BAylBWDOraF1gwBgBVGRzDS_qhnhdgmya1WKY2FbGPfxeukdkEWNB-kYAnTty8WadzIZkcTWInZDXtcP48tb71yHtabqXheFPCMqTVHhyz9l4oXrE5CXrLcP14Fl5e_MMslzoD68BZm4L9pCaE_iNgKmg8LVvPJxzUSM9clGSIt-GKLh8db86HPhY8Y21iDWxeqV6FsHRQk0mYVvWSYzXlXjw";
		let token = jwks.check_jwt(&jwt).unwrap();
		// println!("{:#?}", &token.claims);
		assert_eq!(token.claims["iss"], "git.itsufficient.me");
	}

	#[actix_rt::test]
	async fn validate_jwt() {
		let url = "https://git.itsufficient.me/-/jwks";
		let jwks = Jwks::get(&url).await.unwrap();
		let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1uWDZfVnpJUGFMeHVmV1NVWHZ3Ym16RDNHaEhTY195LVN2Vm1JX3EwUnciLCJ0eXAiOiJKV1QifQ.eyJuYW1lc3BhY2VfaWQiOiI4IiwibmFtZXNwYWNlX3BhdGgiOiJhbHBpbmUiLCJwcm9qZWN0X2lkIjoiOTciLCJwcm9qZWN0X3BhdGgiOiJhbHBpbmUvc3RhdGljc2VydmUiLCJ1c2VyX2lkIjoiMiIsInVzZXJfbG9naW4iOiJlcmljIiwidXNlcl9lbWFpbCI6ImVyaWMuYnVyZ2hhcmRAaXRzdWZmaWNpZW50Lm1lIiwicGlwZWxpbmVfaWQiOiI2NDUiLCJwaXBlbGluZV9zb3VyY2UiOiJwdXNoIiwiam9iX2lkIjoiOTM3IiwicmVmIjoiMC4xLjEiLCJyZWZfdHlwZSI6InRhZyIsInJlZl9wcm90ZWN0ZWQiOiJ0cnVlIiwianRpIjoiMjRkYzU3MDItMGRlMi00MDNhLWFkNzYtOTExZDA0YzhkODc3IiwiaXNzIjoiZ2l0Lml0c3VmZmljaWVudC5tZSIsImlhdCI6MTYzMTg4MjE3MywibmJmIjoxNjMxODgyMTY4LCJleHAiOjE2MzE4ODU3NzMsInN1YiI6ImpvYl85MzcifQ.zCv3W2S9nrMeFEEERuSqa6TzolrQPSw-bXYiVGAzPJXtdEGiDwoLtNRpISrWe4gGZicKA5RgzrW13IrlOxZqIayhKITZo48B_sWYswk7pqcNaWReTrpaKR0mQcR44BAylBWDOraF1gwBgBVGRzDS_qhnhdgmya1WKY2FbGPfxeukdkEWNB-kYAnTty8WadzIZkcTWInZDXtcP48tb71yHtabqXheFPCMqTVHhyz9l4oXrE5CXrLcP14Fl5e_MMslzoD68BZm4L9pCaE_iNgKmg8LVvPJxzUSM9clGSIt-GKLh8db86HPhY8Y21iDWxeqV6FsHRQk0mYVvWSYzXlXjw";
		let claims = Claims::try_from(
			r#"{
			"iss": "git.itsufficient.me",
			"ref_protected": "true",
			"ref_type": "tag",
			"project_path": "alpine/staticserve"
		}"#,
		)
		.unwrap();
		assert_eq!(jwks.validate_jwt(&jwt, &claims).is_ok(), true);
	}

	#[actix_rt::test]
	#[should_panic(expected = "Claim(\"iss\", \"unknown\"")]
	async fn wrong_iss() {
		let url = "https://git.itsufficient.me/-/jwks";
		let jwks = Jwks::get(&url).await.unwrap();
		let jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1uWDZfVnpJUGFMeHVmV1NVWHZ3Ym16RDNHaEhTY195LVN2Vm1JX3EwUnciLCJ0eXAiOiJKV1QifQ.eyJuYW1lc3BhY2VfaWQiOiI4IiwibmFtZXNwYWNlX3BhdGgiOiJhbHBpbmUiLCJwcm9qZWN0X2lkIjoiOTciLCJwcm9qZWN0X3BhdGgiOiJhbHBpbmUvc3RhdGljc2VydmUiLCJ1c2VyX2lkIjoiMiIsInVzZXJfbG9naW4iOiJlcmljIiwidXNlcl9lbWFpbCI6ImVyaWMuYnVyZ2hhcmRAaXRzdWZmaWNpZW50Lm1lIiwicGlwZWxpbmVfaWQiOiI2NDUiLCJwaXBlbGluZV9zb3VyY2UiOiJwdXNoIiwiam9iX2lkIjoiOTM3IiwicmVmIjoiMC4xLjEiLCJyZWZfdHlwZSI6InRhZyIsInJlZl9wcm90ZWN0ZWQiOiJ0cnVlIiwianRpIjoiMjRkYzU3MDItMGRlMi00MDNhLWFkNzYtOTExZDA0YzhkODc3IiwiaXNzIjoiZ2l0Lml0c3VmZmljaWVudC5tZSIsImlhdCI6MTYzMTg4MjE3MywibmJmIjoxNjMxODgyMTY4LCJleHAiOjE2MzE4ODU3NzMsInN1YiI6ImpvYl85MzcifQ.zCv3W2S9nrMeFEEERuSqa6TzolrQPSw-bXYiVGAzPJXtdEGiDwoLtNRpISrWe4gGZicKA5RgzrW13IrlOxZqIayhKITZo48B_sWYswk7pqcNaWReTrpaKR0mQcR44BAylBWDOraF1gwBgBVGRzDS_qhnhdgmya1WKY2FbGPfxeukdkEWNB-kYAnTty8WadzIZkcTWInZDXtcP48tb71yHtabqXheFPCMqTVHhyz9l4oXrE5CXrLcP14Fl5e_MMslzoD68BZm4L9pCaE_iNgKmg8LVvPJxzUSM9clGSIt-GKLh8db86HPhY8Y21iDWxeqV6FsHRQk0mYVvWSYzXlXjw";
		let claims = Claims::try_from(
			r#"{
			"iss": "unknown"
		}"#,
		)
		.unwrap();
		jwks.validate_jwt(&jwt, &claims).unwrap();
	}
}
