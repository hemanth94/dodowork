#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;
    use actix_web::{App, test, web};
    use chrono::{Duration, Utc};
    use dodowork::dodo::logic;
    use dodowork::dodo::logic::AppState;
    use dotenv::dotenv;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use rust_decimal::Decimal;
    use serde_json::json;
    use sqlx::{Executor, PgPool};
    use std::env;
    use std::future::Future;

    use dodowork::dodo::{error::*, jwt::*, logic::*, transaction::*};

    // Helper to setup test app and database
    async fn setup() -> (
        PgPool,
        impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
            Future: Future<Output = Result<actix_web::dev::ServiceResponse, actix_web::Error>>,
        >,
    ) {
        dotenv().ok();
        let database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

        // Connect to test database
        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to test database");

        // Reset database
        pool.execute("TRUNCATE TABLE transactions, users RESTART IDENTITY CASCADE;")
            .await
            .expect("Failed to reset database");

        let app_state = web::Data::new(AppState {
            db_pool: pool.clone(),
            jwt_secret,
        });

        // Initialize test app
        let app = test::init_service(
            App::new().app_data(app_state.clone()).service(
                web::scope("/api")
                    .service(web::resource("/register").route(web::post().to(logic::register)))
                    .service(web::resource("/login").route(web::post().to(logic::login)))
                    .service(
                        web::resource("/transactions")
                            .wrap(JwtMiddleware)
                            .route(web::post().to(logic::create_transaction))
                            .route(web::get().to(logic::get_transactions)),
                    )
                    .service(
                        web::resource("/balance")
                            .wrap(JwtMiddleware)
                            .route(web::get().to(dodowork::dodo::logic::get_balance)),
                    ),
            ),
        )
        .await;

        (pool, app)
    }

    // Helper to generate JWT token
    async fn generate_jwt(user_id: i32, jwt_secret: &str) -> String {
        let expiration = Utc::now() + Duration::hours(24);
        let claims = dodowork::dodo::logic::Claims {
            sub: user_id.to_string(),
            exp: expiration.timestamp() as usize,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_ref()),
        )
        .expect("Failed to generate JWT")
    }

    // Helper to register a user
    async fn register_user(
        _app: &impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
            Future: Future<Output = Result<actix_web::dev::ServiceResponse, actix_web::Error>>,
        >,
        username: &str,
        password: &str,
    ) -> actix_http::Request {
        test::TestRequest::post()
            .uri("/api/register")
            .set_json(json!({
                "username": username,
                "password": password
            }))
            .to_request()
    }

    async fn generate_valid_token() -> String {
        let (pool, app) = setup().await;

        // Register user
        sqlx::query("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 0.00)")
            .bind("testusergx")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .execute(&pool)
            .await
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({
                "username": "testusergx",
                "password": "testpass123"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        body["token"].to_string()
    }

    #[actix_web::test]
    async fn test_register_success() {
        let (_pool, app) = setup().await;

        let req = register_user(&app, "testuserg1", "testpass123").await;
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["message"], "User registered successfully");
    }

    #[actix_web::test]
    async fn test_register_duplicate_username() {
        let (_pool, app) = setup().await;

        // Register first user
        let req = register_user(&app, "testuserg223", "testpass123").await;
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Try to register same username
        let req = register_user(&app, "testuserg223", "differentpass123").await;
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Username already exists");
    }

    #[actix_web::test]
    async fn test_register_empty_credentials() {
        let (_pool, app) = setup().await;

        let req = register_user(&app, "", "").await;
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Username and password cannot be empty");
    }

    #[actix_web::test]
    async fn test_register_short_password() {
        let (_pool, app) = setup().await;

        let req = register_user(&app, "testuserg4", "shor").await;
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Password must be at least 5 characters");
    }

    #[actix_web::test]
    async fn test_login_success() {
        let (pool, app) = setup().await;

        // Register user
        sqlx::query("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 0.00)")
            .bind("testusergx")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .execute(&pool)
            .await
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({
                "username": "testusergx",
                "password": "testpass123"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["token"].is_string());
    }

    #[actix_web::test]
    async fn test_login_invalid_username() {
        let (_pool, app) = setup().await;

        let req = test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({
                "username": "nonexistent",
                "password": "testpass123"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Invalid credentials");
    }

    #[actix_web::test]
    async fn test_login_invalid_password() {
        let (pool, app) = setup().await;

        // Register user
        sqlx::query("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 0.00)")
            .bind("testuserg4")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .execute(&pool)
            .await
            .unwrap();

        let req = test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({
                "username": "testuserg4",
                "password": "wrongpass"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Invalid credentials");
    }

    #[actix_web::test]
    async fn test_login_empty_credentials() {
        let (_pool, app) = setup().await;

        let req = test::TestRequest::post()
            .uri("/api/login")
            .set_json(json!({
                "username": "",
                "password": ""
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Username and password cannot be empty");
    }

    #[actix_web::test]
    async fn test_create_transaction_deposit() {
        let (pool, app) = setup().await;

        // Register user
        let user_id: i32 = sqlx::query_scalar("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 0.00) RETURNING id")
            .bind("testuserg11")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();

        let jwt = generate_jwt(user_id, &env::var("JWT_SECRET").unwrap()).await;

        let req = test::TestRequest::post()
            .uri("/api/transactions")
            .set_json(json!({
                "amount": "111.50",
                "description": "Grocery shopping",
                "transaction_type": "DEPOSIT"
            }))
            .insert_header(("Authorization", format!("Bearer {}", jwt)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["amount"], "111.50");
        assert_eq!(body["description"], "Grocery shopping");
        assert_eq!(body["transaction_type"], "DEPOSIT");

        // Verify balance
        let balance: Decimal = sqlx::query_scalar("SELECT balance FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(balance, Decimal::new(11150, 2));
    }

    #[actix_web::test]
    async fn test_create_transaction_withdrawal_success() {
        let (pool, app) = setup().await;

        // Register user with initial balance
        let user_id: i32 = sqlx::query_scalar("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 200.00) RETURNING id")
            .bind("testuserg12")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();

        let jwt = generate_jwt(user_id, &env::var("JWT_SECRET").unwrap()).await;

        let req = test::TestRequest::post()
            .uri("/api/transactions")
            .set_json(json!({
                "amount": "50.00",
                "description": "ATM withdrawal",
                "transaction_type": "WITHDRAWAL"
            }))
            .insert_header(("Authorization", format!("Bearer {}", jwt)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["amount"], "50.00");
        assert_eq!(body["description"], "ATM withdrawal");
        assert_eq!(body["transaction_type"], "WITHDRAWAL");

        // Verify balance
        let balance: Decimal = sqlx::query_scalar("SELECT balance FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(balance, Decimal::new(15000, 2));
    }

    #[actix_web::test]
    async fn test_create_transaction_insufficient_funds() {
        let (pool, app) = setup().await;

        // Register user with low balance
        let user_id: i32 = sqlx::query_scalar("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 10.00) RETURNING id")
            .bind("testuserg13")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();

        let jwt = generate_jwt(user_id, &env::var("JWT_SECRET").unwrap()).await;

        let req = test::TestRequest::post()
            .uri("/api/transactions")
            .set_json(json!({
                "amount": "50.00",
                "description": "ATM withdrawal",
                "transaction_type": "WITHDRAWAL"
            }))
            .insert_header(("Authorization", format!("Bearer {}", jwt)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Insufficient funds");
    }

    #[actix_web::test]
    async fn test_create_transaction_negative_amount() {
        let (pool, app) = setup().await;

        // Register user
        let user_id: i32 = sqlx::query_scalar("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 0.00) RETURNING id")
            .bind("testuserg14")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();

        let jwt = generate_jwt(user_id, &env::var("JWT_SECRET").unwrap()).await;

        let req = test::TestRequest::post()
            .uri("/api/transactions")
            .set_json(json!({
                "amount": "-10.00",
                "description": "Invalid deposit",
                "transaction_type": "DEPOSIT"
            }))
            .insert_header(("Authorization", format!("Bearer {}", jwt)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Amount must be positive");
    }

    #[actix_web::test]
    async fn test_create_transaction_invalid_type() {
        let (pool, app) = setup().await;

        // Register user
        let user_id: i32 = sqlx::query_scalar("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 0.00) RETURNING id")
            .bind("testuserg15")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();

        let jwt = generate_jwt(user_id, &env::var("JWT_SECRET").unwrap()).await;

        let req = test::TestRequest::post()
            .uri("/api/transactions")
            .set_json(json!({
                "amount": "10.00",
                "description": "Invalid type",
                "transaction_type": "INVALID"
            }))
            .insert_header(("Authorization", format!("Bearer {}", jwt)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(
            body["error"],
            "Invalid input: Transaction type must be DEPOSIT or WITHDRAWAL"
        );
    }

    #[actix_web::test]
    async fn test_create_transaction_invalid_token() {
        let (_pool, app) = setup().await;

        let req = test::TestRequest::post()
            .uri("/api/transactions")
            .set_json(json!({
                "amount": "10.00",
                "description": "Deposit",
                "transaction_type": "DEPOSIT"
            }))
            .insert_header(("Authorization", "Bearer invalid_token"))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let error = body.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert_eq!(error, "Invalid token");
    }

    #[actix_web::test]
    async fn test_get_transactions_success() {
        let (pool, app) = setup().await;

        // Register user
        let user_id: i32 = sqlx::query_scalar("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 0.00) RETURNING id")
            .bind("testuserg16")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();

        // Insert transactions
        sqlx::query("INSERT INTO transactions (user_id, amount, description, transaction_type) VALUES ($1, $2, $3, $4)")
            .bind(user_id)
            .bind(Decimal::new(11150, 2))
            .bind("Grocery shopping")
            .bind(TransactionType::Deposit)
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query("INSERT INTO transactions (user_id, amount, description, transaction_type) VALUES ($1, $2, $3, $4)")
            .bind(user_id)
            .bind(Decimal::new(5000, 2))
            .bind("ATM withdrawal")
            .bind(TransactionType::Withdrawal)
            .execute(&pool)
            .await
            .unwrap();

        let jwt = generate_jwt(user_id, &env::var("JWT_SECRET").unwrap()).await;

        let req = test::TestRequest::get()
            .uri("/api/transactions")
            .insert_header(("Authorization", format!("Bearer {}", jwt)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Vec<serde_json::Value> = test::read_body_json(resp).await;
        assert_eq!(body.len(), 2);
        assert_eq!(body[0]["amount"], "50.00");
        assert_eq!(body[0]["description"], "ATM withdrawal");
        assert_eq!(body[0]["transaction_type"], "WITHDRAWAL");
        assert_eq!(body[1]["amount"], "111.50");
        assert_eq!(body[1]["description"], "Grocery shopping");
        assert_eq!(body[1]["transaction_type"], "DEPOSIT");
    }

    #[actix_web::test]
    async fn test_get_transactions_empty() {
        let (pool, app) = setup().await;

        let user_id: i32 = sqlx::query_scalar("INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, 0.00) RETURNING id")
            .bind("testuserg17")
            .bind(bcrypt::hash("testpass123", bcrypt::DEFAULT_COST).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();

        let jwt = generate_jwt(user_id, &env::var("JWT_SECRET").unwrap()).await;

        let req = test::TestRequest::get()
            .uri("/api/transactions")
            .insert_header(("Authorization", format!("Bearer {}", jwt)))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Vec<serde_json::Value> = test::read_body_json(resp).await;
        assert_eq!(body.len(), 0);
    }

    #[actix_web::test]
    async fn test_get_transactions_invalid_token() {
        let (_pool, app) = setup().await;

        let req = test::TestRequest::get()
            .uri("/api/transactions")
            .insert_header(("Authorization", "Bearer invalid_token"))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let error = body.get("error").and_then(|e| e.as_str()).unwrap_or("");
        assert_eq!(error, "Invalid token");
    }
}
