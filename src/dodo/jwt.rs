use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, web};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use jsonwebtoken::{DecodingKey, Validation, decode};
use std::rc::Rc;

use crate::dodo::logic::{AppState, Claims};

// JWT Middleware
#[derive(Clone)]
pub struct JwtMiddleware;

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareService {
            service: Rc::new(service),
        })
    }
}

pub struct JwtMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            let state = req
                .app_data::<web::Data<AppState>>()
                .ok_or_else(|| actix_web::error::ErrorInternalServerError("App state missing"))?;

            let auth_header = req
                .headers()
                .get("Authorization")
                .ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing token"))?;

            let token = auth_header
                .to_str()
                .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid token"))?
                .replace("Bearer ", "");

            let decoding_key = DecodingKey::from_secret(state.jwt_secret.as_ref());
            let validation = Validation::default();

            let claims = decode::<Claims>(&token, &decoding_key, &validation)
                .map_err(|_| actix_web::error::ErrorUnauthorized("Invalid token"))?
                .claims;

            // Attach user_id to request for use in handlers
            req.extensions_mut().insert(claims.sub);

            // Call the next service
            service.call(req).await
        })
    }
}
