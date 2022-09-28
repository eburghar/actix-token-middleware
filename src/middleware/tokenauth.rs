use actix_utils::future::{ready, Ready};
use actix_web::{
	dev::{ServiceRequest, ServiceResponse, Service, Transform, forward_ready},
	error::ErrorUnauthorized,
	Error,
};
use actix_utils::future::{err, Either};
use std::{
	rc::Rc
};

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.

#[derive(Clone, Default)]
pub struct TokenAuth(Rc<String>);

/*impl Default for TokenAuth {
	fn default() -> Self {
		Self(Rc::new(String::default()))
	}
}*/

impl TokenAuth {
	/// Construct `TokenAuth` middleware.
	pub fn new(token: &str) -> Self {
		Self(Rc::new(token.to_owned()))
	}
}

// Middleware factory is `Transform` trait from actix-service crate
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for TokenAuth
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
	S::Future: 'static,
	B: 'static,
{
	type Response = ServiceResponse<B>;
	type Error = Error;
	type Transform = TokenAuthMiddleware<S>;
	type InitError = ();
	type Future = Ready<Result<Self::Transform, Self::InitError>>;

	fn new_transform(&self, service: S) -> Self::Future {
		ready(Ok(TokenAuthMiddleware {
			service,
			token: self.0.clone(),
		}))
	}
}

pub struct TokenAuthMiddleware<S> {
	service: S,
	token: Rc<String>,
}

impl<S, B> Service<ServiceRequest> for TokenAuthMiddleware<S>
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
	S::Future: 'static,
{
	type Response = ServiceResponse<B>;
	type Error = Error;
	type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

	forward_ready!(service);

	fn call(&self, req: ServiceRequest) -> Self::Future {
		if let Some(token) = req
			.headers()
			.get("token")
			.and_then(|token| token.to_str().ok())
		{
			if token == *self.token {
				return Either::left(self.service.call(req));
			}
		}
		Either::right(err(ErrorUnauthorized("not authorized")))
	}
}
