use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{EncodingKey, Header, encode};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use crate::{
    error::{LoginError, ProtectedError, RegisterError, TransactionError},
    transaction::{Transaction, TransactionType},
};

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
    pub sub: String, // Subject (user id)
    pub exp: usize,  // Expiration
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
    amount: Decimal,
    description: Option<String>,
    transaction_type: TransactionType, // DEPOSIT or WITHDRAWAL
}

// Register handler
pub async fn register(
    req: web::Json<RegisterRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, RegisterError> {
    // Validate input
    if req.username.is_empty() || req.password.is_empty() {
        return Err(RegisterError::InvalidInput(
            "Username and password cannot be empty".into(),
        ));
    }
    if req.password.len() < 8 {
        return Err(RegisterError::InvalidInput(
            "Password must be at least 5 characters".into(),
        ));
    }

    // Check if username exists
    let existing_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&req.username)
        .fetch_optional(&state.db_pool)
        .await;

    if existing_user.unwrap().is_some() {
        return Err(RegisterError::UsernameExists);
    }

    // Hash password
    let password_hash = hash(&req.password, DEFAULT_COST)?;

    // Insert user
    let _result = sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, password_hash"
    )
    .bind(&req.username)
    .bind(&password_hash)
    .fetch_one(&state.db_pool)
    .await?;

    Ok(HttpResponse::Ok().json("User registered successfully"))
}

// Login handler
pub async fn login(
    req: web::Json<LoginRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, LoginError> {
    // Validate input
    if req.username.is_empty() || req.password.is_empty() {
        return Err(LoginError::InvalidInput(
            "Username and password cannot be empty".into(),
        ));
    }

    // Find user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(&req.username)
        .fetch_optional(&state.db_pool)
        .await?
        .ok_or(LoginError::InvalidCredentials)?;

    // Verify password
    if !verify(&req.password, &user.password_hash)? {
        return Err(LoginError::InvalidCredentials);
    }

    // Create JWT
    let expiration = Utc::now() + Duration::hours(24);
    let claims = Claims {
        sub: user.id.to_string(),
        exp: expiration.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_ref()),
    )?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "token": token })))
}

// Create transaction handler
pub async fn create_transaction(
    req: web::Json<TransactionRequest>,
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<HttpResponse, TransactionError> {
    // Extract and parse user_id from request extensions
    let user_id = http_req
        .extensions()
        .get::<String>()
        .ok_or(TransactionError::InvalidToken)?
        .parse::<i32>()
        .map_err(|_| TransactionError::InvalidUserId)?;

    // Validate input
    if req.amount <= Decimal::new(0, 0) {
        return Err(TransactionError::InvalidInput(
            "Amount must be positive".into(),
        ));
    }

    // Start SQL transaction
    let mut tx = state.db_pool.begin().await?;

    // For WITHDRAWAL, check sufficient funds
    if req.transaction_type == TransactionType::Withdrawal {
        let current_balance: String =
            sqlx::query_scalar("SELECT balance::text FROM users WHERE id = $1 FOR UPDATE")
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
        let balance: Decimal = current_balance
            .parse()
            .map_err(|_| TransactionError::ParseError)?;
        if balance < req.amount {
            return Err(TransactionError::InsufficientFunds);
        }
    }

    // Insert transaction
    let transaction = sqlx::query_as::<_, Transaction>(
        "INSERT INTO transactions (user_id, amount, description, transaction_type) VALUES ($1, $2, $3, $4) RETURNING id, user_id, amount::text, description, created_at, transaction_type"
    )
    .bind(user_id)
    .bind(req.amount)
    .bind(&req.description)
    .bind(&req.transaction_type)
    .fetch_one(&mut *tx)
    .await?;

    // Update balance
    let balance_update_query = match req.transaction_type {
        TransactionType::Deposit => "UPDATE users SET balance = balance + $1 WHERE id = $2",
        TransactionType::Withdrawal => "UPDATE users SET balance = balance - $1 WHERE id = $2",
    };
    sqlx::query(balance_update_query)
        .bind(req.amount)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // Commit transaction
    tx.commit().await?;

    Ok(HttpResponse::Ok().json(transaction))
}

// Get user transactions handler
pub async fn get_transactions(
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<HttpResponse, TransactionError> {
    let user_id = http_req
        .extensions()
        .get::<String>()
        .ok_or(TransactionError::InvalidToken)?
        .parse::<i32>()
        .map_err(|_| TransactionError::InvalidUserId)?;

    let transactions = sqlx::query_as::<_, Transaction>(
        "SELECT id, user_id, amount::text, description, created_at FROM transactions WHERE user_id = $1 ORDER BY created_at DESC"
    )
    .bind(user_id)
    .fetch_all(&state.db_pool)
    .await?;

    Ok(HttpResponse::Ok().json(transactions))
}

// Get user balance handler
pub async fn get_balance(
    state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<HttpResponse, TransactionError> {
    let user_id = http_req
        .extensions()
        .get::<String>()
        .ok_or(TransactionError::InvalidToken)?
        .parse::<i32>()
        .map_err(|_| TransactionError::InvalidUserId)?;

    let balance: String = sqlx::query_scalar("SELECT balance::text FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db_pool)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "balance": balance })))
}

// Protected route handler
pub async fn protected_route(
    _state: web::Data<AppState>,
    http_req: HttpRequest,
) -> Result<HttpResponse, ProtectedError> {
    let user_id = http_req
        .extensions()
        .get::<String>()
        .ok_or(ProtectedError::InvalidToken)?
        .parse::<i32>()
        .map_err(|_| ProtectedError::InvalidUserId)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Protected route accessed by user ID {}", user_id)
    })))
}
