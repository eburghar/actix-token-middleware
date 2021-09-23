Define 2 middlewares one can use to protect url under actix-web:

- `TokenAuth` is a simple middleware that will just check that a header `Token: xxxx` is present in the request and
  match a static value,
- `JwtAuth` will check that a header `Authorization: Bearer xxxx` is present, decode the JWT Token, verify the
  validity and its signature with keys retrieved from a JWKS endpoint, and then check for the presence of
  predefined claims values.

`JwtAuth` is useful with [Gitlab](https://docs.gitlab.com/ee/ci/secrets/), allowing you to replace static secret
(generally passed to ci/cd pipeline through [protected variables](https://docs.gitlab.com/ee/ci/variables/)) with
a more secure mechanism (asymmetrical cryptography). You can protect urls by trusting gitlab short-lived secret
`CI_JOB_JWT` issued during CI/CD job execution. The claims can be used to certify that the access request is coming
from a job from a given project, namespace, protected branch or tag, ...

```rust
use actix_token_middleware::{
	jwt::{Claims, Jwks},
	jwtauth::JwtAuth,
};
use actix_web::{get, HttpResponse, HttpServer};

/// wrap protected in JwtAuth middleware
#[get("/protected", wrap = "JwtAuth")]
async fn protected() -> HttpResponse {
	HttpResponse::Ok().body("protected url granted !")
}

async fn serve() -> Result<()> {
    // get jwks
    let jwks = Jwks::get("https://gitlab.com/-/jwks").await.unwrap();
    // create claims map from a json string
    let claims = Claims::try_from("{ \"iss\": \"example.com\" }");
    // turn jwks and claims accessible to extractors
    let server = HttpServer::new(move || {
    	App::new()
    		.data(jwks.clone())
    		.data(claims.clone())
    		.service(protected);
    // serve
	server.await?;
	Ok(())
```
