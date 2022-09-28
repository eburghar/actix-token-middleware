use crate::data::Jwt;

use actix_utils::future::{err, ok, Either, Ready};
use actix_web::{
	dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
	error::ErrorUnauthorized,
	http::header::AUTHORIZATION,
	Error,
};
use std::rc::Rc;

#[derive(Clone)]
/// Middleware factory than instanciate JwtAuthMiddleware
pub struct JwtAuth(Rc<Jwt>);

impl JwtAuth {
	/// Construct a JwtAuth instance that forwards a Jwt struct to all its middleware
	pub fn new(jwt: Jwt) -> Self {
		Self(Rc::new(jwt))
	}
}

// Middleware factory is `Transform` trait from actix-service crate
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
	S::Future: 'static,
	B: 'static,
{
	type Response = ServiceResponse<B>;
	type Error = Error;
	type Transform = JwtAuthMiddleware<S>;
	type InitError = ();
	type Future = Ready<Result<Self::Transform, Self::InitError>>;

	fn new_transform(&self, service: S) -> Self::Future {
		ok(JwtAuthMiddleware {
			service,
			jwt: self.0.clone(),
		})
	}
}

pub struct JwtAuthMiddleware<S> {
	service: S,
	jwt: Rc<Jwt>,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
	S::Future: 'static,
{
	type Response = ServiceResponse<B>;
	type Error = Error;
	type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

	forward_ready!(service);

	fn call(&self, req: ServiceRequest) -> Self::Future {
		if let Some(jwt) = req
			.headers()
			.get(AUTHORIZATION)
			.and_then(|token| token.to_str().ok())
			.and_then(|token| token.find("Bearer: ").map(|_| &token[8..]))
		{
			self.jwt
				.validate_jwt(jwt)
				.map(|_| Either::left(self.service.call(req)))
				.unwrap_or_else(|e| {
					Either::right(err(ErrorUnauthorized(format!("Not authorized - {}", e))))
				})
		} else {
			Either::right(err(ErrorUnauthorized(
				"Not authorized - Missing bearer token",
			)))
		}
	}
}
