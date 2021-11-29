use crate::result::{Error, Result};

use actix_web::client::Client;
use serde_vecmap::vecmap;
use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde::Deserialize;
use serde_json::Value;
use std::str::from_utf8;

#[derive(Deserialize, Clone, Default)]
pub struct Jwt {
	// jwks endpoint
	jwks: String,
	// keys
	#[serde(skip)]
	keys: Vec<jwk::JsonWebKey>,
	// claims to validate the JWT tokens against
	#[serde(default)]
	#[serde(with = "vecmap")]
	claims: Vec<(String, String)>,
}

impl Jwt {
	pub async fn new(jwks: &str, claims: Vec<(String, String)>) -> Result<Self> {
		let keys = Jwks::get(jwks).await?;
		Ok(Self {
			jwks: jwks.to_owned(),
			keys: keys.keys,
			claims,
		})
	}

	/// Check that all claims are in tokendata and match expected data
	pub fn check_claims(&self, tokendata: &jwt::TokenData<Value>) -> Result<()> {
		for valid in self.claims.iter().map(|(key, val)| {
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
			// propagate errors if any
			let _ = valid?;
		}
		Ok(())
	}

	pub async fn set_keys(&mut self) -> Result<()> {
		let keys = Jwks::get(&self.jwks).await?;
		self.keys = keys.keys;
		Ok(())
	}

	/// Return the JsonWebKey corresponding to the given kid
	fn get_key(&self, kid: &str) -> Option<&jwk::JsonWebKey> {
		self.keys
			.iter()
			.find(|k| k.key_id.as_ref().filter(|id| *id == kid).is_some())
	}

	/// Check the jwt (expiration, signature, ...)
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

	/// Ensure that all claims are present in the token with expected values
	pub fn validate_jwt(&self, jwt: &str) -> Result<()> {
		let tokendata = self.check_jwt(jwt)?;
		for valid in self.claims.iter().map(|(key, val)| {
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

#[derive(Debug, Deserialize, Clone)]
/// Deserialise keys from a jwks endpoint response
struct Jwks {
	keys: Vec<jwk::JsonWebKey>,
}

impl Jwks {
	/// Initialize a Jwks from a given url
	async fn get(url: &str) -> Result<Self> {
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
		let jwt = Jwt::new("https://git.itsufficient.me/-/jwks", Vec::default())
			.await
			.unwrap();
		assert_eq!(
			jwt.get_key("MnX6_VzIPaLxufWSUXvwbmzD3GhHSc_y-SvVmI_q0Rw")
				.is_some(),
			true
		);
	}

	#[actix_rt::test]
	async fn check_jwt() {
		let jwt = Jwt::new("https://git.itsufficient.me/-/jwks", Vec::default())
			.await
			.unwrap();
		let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1uWDZfVnpJUGFMeHVmV1NVWHZ3Ym16RDNHaEhTY195LVN2Vm1JX3EwUnciLCJ0eXAiOiJKV1QifQ.eyJuYW1lc3BhY2VfaWQiOiI4IiwibmFtZXNwYWNlX3BhdGgiOiJhbHBpbmUiLCJwcm9qZWN0X2lkIjoiOTciLCJwcm9qZWN0X3BhdGgiOiJhbHBpbmUvc3RhdGljc2VydmUiLCJ1c2VyX2lkIjoiMiIsInVzZXJfbG9naW4iOiJlcmljIiwidXNlcl9lbWFpbCI6ImVyaWMuYnVyZ2hhcmRAaXRzdWZmaWNpZW50Lm1lIiwicGlwZWxpbmVfaWQiOiI2NDUiLCJwaXBlbGluZV9zb3VyY2UiOiJwdXNoIiwiam9iX2lkIjoiOTM3IiwicmVmIjoiMC4xLjEiLCJyZWZfdHlwZSI6InRhZyIsInJlZl9wcm90ZWN0ZWQiOiJ0cnVlIiwianRpIjoiMjRkYzU3MDItMGRlMi00MDNhLWFkNzYtOTExZDA0YzhkODc3IiwiaXNzIjoiZ2l0Lml0c3VmZmljaWVudC5tZSIsImlhdCI6MTYzMTg4MjE3MywibmJmIjoxNjMxODgyMTY4LCJleHAiOjE2MzE4ODU3NzMsInN1YiI6ImpvYl85MzcifQ.zCv3W2S9nrMeFEEERuSqa6TzolrQPSw-bXYiVGAzPJXtdEGiDwoLtNRpISrWe4gGZicKA5RgzrW13IrlOxZqIayhKITZo48B_sWYswk7pqcNaWReTrpaKR0mQcR44BAylBWDOraF1gwBgBVGRzDS_qhnhdgmya1WKY2FbGPfxeukdkEWNB-kYAnTty8WadzIZkcTWInZDXtcP48tb71yHtabqXheFPCMqTVHhyz9l4oXrE5CXrLcP14Fl5e_MMslzoD68BZm4L9pCaE_iNgKmg8LVvPJxzUSM9clGSIt-GKLh8db86HPhY8Y21iDWxeqV6FsHRQk0mYVvWSYzXlXjw";
		let token = jwt.check_jwt(&token).unwrap();
		// println!("{:#?}", &token.claims);
		assert_eq!(token.claims["iss"], "git.itsufficient.me");
	}

	#[actix_rt::test]
	async fn validate_jwt() {
		let jwt = Jwt::new(
			"https://git.itsufficient.me/-/jwks",
			vec![
				("iss".to_owned(), "git.itsufficient.me".to_owned()),
				("ref_protected".to_owned(), "true".to_owned()),
				("ref_type".to_owned(), "tag".to_owned()),
				("project_path".to_owned(), "alpine/staticserve".to_owned()),
			],
		)
		.await
		.unwrap();
		let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1uWDZfVnpJUGFMeHVmV1NVWHZ3Ym16RDNHaEhTY195LVN2Vm1JX3EwUnciLCJ0eXAiOiJKV1QifQ.eyJuYW1lc3BhY2VfaWQiOiI4IiwibmFtZXNwYWNlX3BhdGgiOiJhbHBpbmUiLCJwcm9qZWN0X2lkIjoiOTciLCJwcm9qZWN0X3BhdGgiOiJhbHBpbmUvc3RhdGljc2VydmUiLCJ1c2VyX2lkIjoiMiIsInVzZXJfbG9naW4iOiJlcmljIiwidXNlcl9lbWFpbCI6ImVyaWMuYnVyZ2hhcmRAaXRzdWZmaWNpZW50Lm1lIiwicGlwZWxpbmVfaWQiOiI2NDUiLCJwaXBlbGluZV9zb3VyY2UiOiJwdXNoIiwiam9iX2lkIjoiOTM3IiwicmVmIjoiMC4xLjEiLCJyZWZfdHlwZSI6InRhZyIsInJlZl9wcm90ZWN0ZWQiOiJ0cnVlIiwianRpIjoiMjRkYzU3MDItMGRlMi00MDNhLWFkNzYtOTExZDA0YzhkODc3IiwiaXNzIjoiZ2l0Lml0c3VmZmljaWVudC5tZSIsImlhdCI6MTYzMTg4MjE3MywibmJmIjoxNjMxODgyMTY4LCJleHAiOjE2MzE4ODU3NzMsInN1YiI6ImpvYl85MzcifQ.zCv3W2S9nrMeFEEERuSqa6TzolrQPSw-bXYiVGAzPJXtdEGiDwoLtNRpISrWe4gGZicKA5RgzrW13IrlOxZqIayhKITZo48B_sWYswk7pqcNaWReTrpaKR0mQcR44BAylBWDOraF1gwBgBVGRzDS_qhnhdgmya1WKY2FbGPfxeukdkEWNB-kYAnTty8WadzIZkcTWInZDXtcP48tb71yHtabqXheFPCMqTVHhyz9l4oXrE5CXrLcP14Fl5e_MMslzoD68BZm4L9pCaE_iNgKmg8LVvPJxzUSM9clGSIt-GKLh8db86HPhY8Y21iDWxeqV6FsHRQk0mYVvWSYzXlXjw";
		assert_eq!(jwt.validate_jwt(token).is_ok(), true);
	}

	#[actix_rt::test]
	#[should_panic(expected = "Claim(\"iss\", \"unknown\"")]
	async fn wrong_iss() {
		let jwt = Jwt::new("https://git.itsufficient.me/-/jwks", Vec::default())
			.await
			.unwrap();
		let token= "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1uWDZfVnpJUGFMeHVmV1NVWHZ3Ym16RDNHaEhTY195LVN2Vm1JX3EwUnciLCJ0eXAiOiJKV1QifQ.eyJuYW1lc3BhY2VfaWQiOiI4IiwibmFtZXNwYWNlX3BhdGgiOiJhbHBpbmUiLCJwcm9qZWN0X2lkIjoiOTciLCJwcm9qZWN0X3BhdGgiOiJhbHBpbmUvc3RhdGljc2VydmUiLCJ1c2VyX2lkIjoiMiIsInVzZXJfbG9naW4iOiJlcmljIiwidXNlcl9lbWFpbCI6ImVyaWMuYnVyZ2hhcmRAaXRzdWZmaWNpZW50Lm1lIiwicGlwZWxpbmVfaWQiOiI2NDUiLCJwaXBlbGluZV9zb3VyY2UiOiJwdXNoIiwiam9iX2lkIjoiOTM3IiwicmVmIjoiMC4xLjEiLCJyZWZfdHlwZSI6InRhZyIsInJlZl9wcm90ZWN0ZWQiOiJ0cnVlIiwianRpIjoiMjRkYzU3MDItMGRlMi00MDNhLWFkNzYtOTExZDA0YzhkODc3IiwiaXNzIjoiZ2l0Lml0c3VmZmljaWVudC5tZSIsImlhdCI6MTYzMTg4MjE3MywibmJmIjoxNjMxODgyMTY4LCJleHAiOjE2MzE4ODU3NzMsInN1YiI6ImpvYl85MzcifQ.zCv3W2S9nrMeFEEERuSqa6TzolrQPSw-bXYiVGAzPJXtdEGiDwoLtNRpISrWe4gGZicKA5RgzrW13IrlOxZqIayhKITZo48B_sWYswk7pqcNaWReTrpaKR0mQcR44BAylBWDOraF1gwBgBVGRzDS_qhnhdgmya1WKY2FbGPfxeukdkEWNB-kYAnTty8WadzIZkcTWInZDXtcP48tb71yHtabqXheFPCMqTVHhyz9l4oXrE5CXrLcP14Fl5e_MMslzoD68BZm4L9pCaE_iNgKmg8LVvPJxzUSM9clGSIt-GKLh8db86HPhY8Y21iDWxeqV6FsHRQk0mYVvWSYzXlXjw";
		jwt.validate_jwt(token).unwrap();
	}
}
