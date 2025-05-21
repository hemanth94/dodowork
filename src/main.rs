use actix_web::{App, HttpServer, middleware, web};
use dotenv::dotenv;
use jwt::JwtMiddleware;
use log::error;
pub use logic::{AppState, create_transaction, get_balance, get_transactions, login, register};
use sqlx::PgPool;
use std::env;

pub mod error;
pub mod jwt;
pub mod logic;
pub mod transaction;

// use dodowork::{jwt::*, error::*, logic::*, transaction::*};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // Initialize database connection
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Initialize app state
    let app_state = web::Data::new(AppState {
        db_pool,
        jwt_secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
    });
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(middleware::Logger::default())
            .service(
                web::scope("/api")
                    .service(web::resource("/register").route(web::post().to(
                        |req, state| async move {
                            match register(req, state).await {
                                Ok(resp) => resp,
                                Err(e) => e.to_response(),
                            }
                        },
                    )))
                    .service(web::resource("/login").route(web::post().to(
                        |req, state| async move {
                            match login(req, state).await {
                                Ok(resp) => resp,
                                Err(e) => e.to_response(),
                            }
                        },
                    )))
                    .service(
                        web::resource("/transactions")
                            .wrap(JwtMiddleware) // Apply JWT middleware
                            .route(web::post().to(|req, state, http_req| async move {
                                match create_transaction(req, state, http_req).await {
                                    Ok(resp) => resp,
                                    Err(e) => {
                                        error!("Transaction creation error: {:?}", e);
                                        e.to_response()
                                    }
                                }
                            }))
                            .route(web::get().to(|state, http_req| async move {
                                match get_transactions(state, http_req).await {
                                    Ok(resp) => resp,
                                    Err(e) => {
                                        error!("Transaction fetch error: {:?}", e);
                                        e.to_response()
                                    }
                                }
                            })),
                    )
                    .service(
                        web::resource("/balance")
                            .wrap(JwtMiddleware)
                            .route(web::get().to(|state, http_req| async move {
                                match get_balance(state, http_req).await {
                                    Ok(resp) => resp,
                                    Err(e) => {
                                        error!("Balance fetch error: {:?}", e);
                                        e.to_response()
                                    }
                                }
                            })),
                    ),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
