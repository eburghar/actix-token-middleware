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
use actix_token_middleware::{data::Jwt, middleware::jwtauth::JwtAuth};
use actix_web::{get, HttpResponse, HttpServer};

async fn protected() -> HttpResponse {
	HttpResponse::Ok().body("protected url granted !")
}

async fn serve() -> Result<()> {
    // Structure to drive the JwtAuthMiddleware instanciated by JwtAuth factory (can be deserialized with serde)
    let jwt = Jwt::new("https://gitlab.com/-/jwks", vec![("iss", "example.com"]).await.unwrap();
    let server = HttpServer::new(move || {
        App::new()
            .service(
                web::resource("/protected")
                    .wrap(JwtAuth::new(jwt))
                    .route(web::post().to(upload)),
            );
    // serve
    server.await?;
    Ok(())
}
```
