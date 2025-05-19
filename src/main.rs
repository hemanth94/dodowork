use actix_web::{App, HttpServer, Result, middleware, web};
use dotenv::dotenv;
use logic::{
    AppState, JwtMiddleware, create_transaction, get_transactions, login, protected_route, register,
};
use serde::Deserialize;
use sqlx::PgPool;
use std::env;
mod logic;

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
            .wrap(JwtMiddleware) // Apply JWT middleware
            .service(
                web::scope("/api")
                    .service(web::resource("/register").route(web::post().to(register)))
                    .service(web::resource("/login").route(web::post().to(login)))
                    .service(
                        web::resource("/transactions")
                            .route(web::post().to(create_transaction))
                            .route(web::get().to(get_transactions)),
                    )
                    .service(web::resource("/protected").route(web::get().to(protected_route))),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

#[derive(Deserialize)]
struct Info {
    username: String,
    mobile: String,
}

async fn user_registration(info: web::Json<Info>) -> Result<String> {
    Ok(format!("Welcome {}!", info.mobile))
}
