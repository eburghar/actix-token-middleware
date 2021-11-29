use crate::data::Jwt;

use actix_service::{Service, Transform};
use actix_web::{
	dev::{ServiceRequest, ServiceResponse},
	error::ErrorUnauthorized,
	http::header::AUTHORIZATION,
	Error,
};
use futures::future::{err, ok, Either, Ready};
use std::{
	rc::Rc,
	task::{Context, Poll},
};

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
impl<S, B> Transform<S> for JwtAuth
where
	S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
	S::Future: 'static,
	B: 'static,
{
	type Request = ServiceRequest;
	type Response = ServiceResponse<B>;
	type Error = Error;
	type InitError = ();
	type Transform = JwtAuthMiddleware<S>;
	type Future = Ready<Result<Self::Transform, Self::InitError>>;

	fn new_transform(&self, service: S) -> Self::Future {
		ok(JwtAuthMiddleware { service, jwt: self.0.clone() })
	}
}

pub struct JwtAuthMiddleware<S> {
	service: S,
	jwt: Rc<Jwt>
}

impl<S, B> Service for JwtAuthMiddleware<S>
where
	S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
	S::Future: 'static,
{
	type Request = ServiceRequest;
	type Response = ServiceResponse<B>;
	type Error = Error;
	type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.service.poll_ready(cx)
	}

	fn call(&mut self, req: ServiceRequest) -> Self::Future {
		if let Some(jwt) = req
			.headers()
			.get(AUTHORIZATION)
			.and_then(|token| token.to_str().ok())
			.and_then(|token| token.find("Bearer ").and_then(|_| Some(&token[7..])))
		{
			return self.jwt
				.validate_jwt(jwt)
				.map(|_| Either::Left(self.service.call(req)))
				.unwrap_or_else(|e| {
					Either::Right(err(ErrorUnauthorized(format!("Not authorized - {}", e))))
				});
		}
		Either::Right(err(ErrorUnauthorized(
			"Not authorized - Missing bearer token",
		)))
	}
}
