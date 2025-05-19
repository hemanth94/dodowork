use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage, HttpRequest, HttpResponse, Responder, web};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use std::rc::Rc;

// User data structure
#[derive(Serialize, Deserialize, FromRow, Clone)]
struct User {
    id: i32,
    username: String,
    password_hash: String,
}

// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String, // Subject (user id)
    exp: usize,  // Expiration
}

// Transaction data structure
#[derive(Serialize, Deserialize, FromRow)]
pub struct Transaction {
    id: i32,
    user_id: i32,
    amount: f64,
    description: Option<String>,
    created_at: chrono::DateTime<Utc>,
}

// App state
pub struct AppState {
    pub db_pool: PgPool,
    pub jwt_secret: String,
}

// Login request payload
#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

// Register request payload
#[derive(Deserialize)]
pub struct RegisterRequest {
    username: String,
    password: String,
}

// Transaction request payload
#[derive(Deserialize)]
pub struct TransactionRequest {
    amount: f64,
    description: Option<String>,
}

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

// Register handler
pub async fn register(
    req: web::Json<RegisterRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    // Check if username exists
    let existing_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&req.username)
        .fetch_optional(&state.db_pool)
        .await;

    if existing_user.is_ok() && existing_user.unwrap().is_some() {
        return HttpResponse::Conflict().json("Username already exists");
    }

    // Hash password
    let password_hash = match hash(&req.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json("Hashing error"),
    };

    // Insert user
    let result = sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, password_hash"
    )
    .bind(&req.username)
    .bind(&password_hash)
    .fetch_one(&state.db_pool)
    .await;

    match result {
        Ok(_) => HttpResponse::Ok().json("User registered successfully"),
        Err(_) => HttpResponse::InternalServerError().json("Database error"),
    }
}

// Login handler
pub async fn login(req: web::Json<LoginRequest>, state: web::Data<AppState>) -> impl Responder {
    // Find user
    let user = match sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&req.username)
        .fetch_optional(&state.db_pool)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return HttpResponse::Unauthorized().json("Invalid credentials"),
        Err(_) => return HttpResponse::InternalServerError().json("Database error"),
    };

    // Verify password
    let valid = match verify(&req.password, &user.password_hash) {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().json("Verification error"),
    };

    if !valid {
        return HttpResponse::Unauthorized().json("Invalid credentials");
    }

    // Create JWT
    let expiration = Utc::now() + Duration::hours(24);
    let claims = Claims {
        sub: user.id.to_string(),
        exp: expiration.timestamp() as usize,
    };

    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_ref()),
    ) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json("Token creation error"),
    };

    HttpResponse::Ok().json(serde_json::json!({ "token": token }))
}

// Create transaction handler
pub async fn create_transaction(
    req: web::Json<TransactionRequest>,
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> impl Responder {
    // Extract and parse user_id from request extensions
    let user_id = match http_req.extensions().get::<String>() {
        Some(id_str) => match id_str.parse::<i32>() {
            Ok(id) => id,
            Err(_) => return HttpResponse::Unauthorized().json("Invalid user ID"),
        },
        None => return HttpResponse::Unauthorized().json("Invalid token"),
    };

    // Perform database query
    let result = sqlx::query_as::<_, Transaction>(
        "INSERT INTO transactions (user_id, amount, description) VALUES ($1, $2, $3) RETURNING id, user_id, amount, description, created_at"
    )
    .bind(user_id)
    .bind(req.amount)
    .bind(&req.description)
    .fetch_one(&state.db_pool)
    .await;

    match result {
        Ok(transaction) => HttpResponse::Ok().json(transaction),
        Err(_) => HttpResponse::InternalServerError().json("Database error"),
    }
}

// Get user transactions handler
pub async fn get_transactions(state: web::Data<AppState>, http_req: HttpRequest) -> impl Responder {
    // Extract and parse user_id from request extensions
    let user_id = match http_req.extensions().get::<String>() {
        Some(id_str) => match id_str.parse::<i32>() {
            Ok(id) => id,
            Err(_) => return HttpResponse::Unauthorized().json("Invalid user ID"),
        },
        None => return HttpResponse::Unauthorized().json("Invalid token"),
    };

    // Perform database query
    let transactions = sqlx::query_as::<_, Transaction>(
        "SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db_pool)
    .await;

    // Handle query result
    match transactions {
        Ok(transactions) => HttpResponse::Ok().json(transactions),
        Err(_) => HttpResponse::InternalServerError().json("Database error"),
    }
}

// Protected route example
pub async fn protected_route(_: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json("This is a protected route")
}
