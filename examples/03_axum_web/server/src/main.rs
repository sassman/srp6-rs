use std::net::SocketAddr;

use axum::{Json, Router, response::IntoResponse, routing};
use tokio::net::TcpListener;

use srp6_shared_data::{UserRegistration, UserRegistrationJson};

#[tokio::main]
async fn main() {
    let app = axum::Router::new()
        .route("/", routing::get(greet))
        .route("/register", routing::post(register));

    serve(app).await;
}

async fn serve(app: Router) {
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(&addr).await.unwrap();

    eprintln!("webserver started: http://0.0.0.0:3000/");
    axum::serve(listener, app).await.unwrap();
}

async fn greet() -> Result<impl IntoResponse, ()> {
    Ok(Json("Hello, World!"))
}

async fn register(user_data: Json<UserRegistrationJson>) -> Result<impl IntoResponse, ()> {
    let hello = format!("Registered {}", user_data.username);
    let data = UserRegistration::from(user_data.0);

    Ok(Json(hello, data))
}
