use actix_web::{Error, HttpResponse, http::StatusCode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Password verification error: {0}")]
    Verification(#[from] bcrypt::BcryptError),
    #[error("Token creation error: {0}")]
    Token(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Invalid token")]
    InvalidToken,
    #[error("Invalid user ID")]
    InvalidUserId,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Parsing error")]
    ParseError,
}

#[derive(Error, Debug)]
pub enum RegisterError {
    #[error("Username already exists")]
    UsernameExists,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Password hashing error: {0}")]
    Hashing(#[from] bcrypt::BcryptError),
    #[error("Token creation error: {0}")]
    Token(#[from] jsonwebtoken::errors::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl LoginError {
    pub fn to_response(&self) -> HttpResponse {
        let msg = self.to_string();
        HttpResponse::build(match self {
            LoginError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            LoginError::Database(_) | LoginError::Verification(_) | LoginError::Token(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            LoginError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        })
        .json(serde_json::json!({ "error": msg }))
    }
}

impl From<LoginError> for Error {
    fn from(err: LoginError) -> Self {
        actix_web::error::ErrorInternalServerError(err)
    }
}

// Convert TransactionError to HttpResponse
impl TransactionError {
    pub fn to_response(&self) -> HttpResponse {
        let msg = self.to_string();
        HttpResponse::build(match self {
            TransactionError::InvalidToken
            | TransactionError::InvalidUserId
            | TransactionError::InsufficientFunds => StatusCode::UNAUTHORIZED,
            TransactionError::InvalidInput(_) => StatusCode::BAD_REQUEST,

            TransactionError::Database(_) | TransactionError::ParseError => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })
        .json(serde_json::json!({ "error": msg }))
    }
}

// Implement From<TransactionError> for actix_web::Error
impl From<TransactionError> for Error {
    fn from(err: TransactionError) -> Self {
        actix_web::error::ErrorInternalServerError(err)
    }
}

impl RegisterError {
    pub fn to_response(&self) -> HttpResponse {
        let msg = self.to_string();
        HttpResponse::build(match self {
            RegisterError::UsernameExists => StatusCode::CONFLICT,
            RegisterError::Database(_) | RegisterError::Hashing(_) | RegisterError::Token(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            RegisterError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        })
        .json(serde_json::json!({ "error": msg }))
    }
}

impl From<RegisterError> for Error {
    fn from(err: RegisterError) -> Self {
        actix_web::error::ErrorInternalServerError(err)
    }
}
