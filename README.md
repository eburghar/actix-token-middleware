Define 2 middlewares one can use to protect url under actix-web:

- `TokenAuth` is a simple middleware that will just check that a header `Token: xxxx` is present in the request and
  match a static value,
- `JwtAuth` will check that a header `Authorization: Bearer xxxx` is present, decode the JWT Token, verify the
  validity and its signature with keys retrieved from a JWKS endpoint, and then check for the presence of
  predefined claims values.

`JwtAuth` is useful with [Gitlab](https://docs.gitlab.com/ee/ci/secrets/) allowing to protect url by trusting
gitlab short-lived secret `CI_JOB_JWT`. The claims can be used to certify that the access is coming from a given
project, namespace, branch, tag or protected area.


```rust
use actix_token_middleware::{
	jwt::{Claims, Jwks},
	jwtauth::JwtAuth,
};
use actix_web::{middleware::Logger, post, web, App, Error, HttpResponse, HttpServer};

/// wrap protected in JwtAuth middleware
#[post("/protected", wrap = "JwtAuth")]
async fn protected() -> HttpResponse {
	HttpResponse::Ok().body("protected url granted !")
}

async fn serve() -> Result<()> {
    // get jwks
    let jwks = Jwks::get("https://gitlab.com/-/jwks").await.unwrap();
    // create claims map from a json string
    let claims = Claims::try_from("{ \"iss\": \"example.com\" }");
    let server = HttpServer::new(move || {
    	App::new()
    		.data(jwks.clone())
    		.data(claims.clone())
    		.servive(protected);
	server.await?;
	Ok(())
```
