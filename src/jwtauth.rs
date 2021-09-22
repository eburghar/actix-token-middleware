use crate::jwt::{Claims, Jwks};

use actix_service::{Service, Transform};
use actix_web::{
	dev::{ServiceRequest, ServiceResponse},
	error::ErrorUnauthorized,
	http::header::AUTHORIZATION,
	web::Data,
	Error,
};
use futures::future::{err, ok, Either, Ready};
use std::task::{Context, Poll};

// There are two steps in middleware processing.
// 1. Middleware initialization, middleware factory gets called with
//    next service in chain as parameter.
// 2. Middleware's call method gets called with normal request.
pub struct JwtAuth;

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
		ok(JwtAuthMiddleware { service })
	}
}

pub struct JwtAuthMiddleware<S> {
	service: S,
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
			if let Some(jwks) = req.app_data::<Data<Jwks>>() {
				if let Some(claims) = req.app_data::<Data<Claims>>() {
					let ref claims = **claims.clone().into_inner();
					return jwks
						.validate_jwt(jwt, claims)
						.map(|_| Either::Left(self.service.call(req)))
						.unwrap_or_else(|e| {
							Either::Right(err(ErrorUnauthorized(format!("Not authorized - {}", e))))
						});
				}
			}
		}
		Either::Right(err(ErrorUnauthorized("Not authorized - Missing bearer token")))
	}
}
