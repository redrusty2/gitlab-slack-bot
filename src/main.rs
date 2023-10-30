//! This is an example function that leverages the Lambda Rust runtime's HTTP support
//! and the [axum](https://docs.rs/axum/latest/axum/index.html) web framework.  The
//! runtime HTTP support is backed by the [tower::Service](https://docs.rs/tower-service/0.3.2/tower_service/trait.Service.html)
//! trait.  Axum applications are also backed by the `tower::Service` trait.  That means
//! that it is fairly easy to build an Axum application and pass the resulting `Service`
//! implementation to the Lambda runtime to run as a Lambda function.  By using Axum instead
//! of a basic `tower::Service` you get web framework niceties like routing, request component
//! extraction, validation, etc.

use axum::{
    extract::Path,
    http::Request,
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use hmac::{Hmac, Mac};
use hyper::StatusCode;
use lambda_http::{run, Error};
use serde_json::{json, Value};
use sha2::Sha256;
use once_cell::sync::Lazy;

type HmacSha256 = Hmac<Sha256>;

static SLACK_SIGNING_SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("SLACK_SIGNING_SECRET").expect("SLACK_SIGNING_SECRET is not set.")
});

async fn validate_slack_signature(
    mut request: Request<lambda_http::Body>,
    next: Next<lambda_http::Body>,
) -> Response {
    tracing::info!(request = ?request, "request");

    let timestamp = &request
        .headers()
        .get("X-Slack-Request-Timestamp")
        .expect("X-Slack-Request-Timestamp header is missing")
        .to_owned();
    let timestamp_str = timestamp.to_str().unwrap();

    let body = request.body_mut();
    let body_copy = body.clone();
    let body_str = String::from_utf8(body_copy.to_vec()).unwrap();

    let base_string = format!("v0:{}:{}", timestamp_str, body_str);
    let mut mac = HmacSha256::new_from_slice(SLACK_SIGNING_SECRET.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(base_string.as_bytes());
    let result: String = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect();

    // let result = mac.verify_slice(
    //     request
    //         .headers()
    //         .get("X-Slack-Signature")
    //         .expect("X-Slack-Signature header is missing")
    //         .to_str()
    //         .unwrap()
    //         .as_bytes(),
    // );
    let expected_signature = request
            .headers()
            .get("X-Slack-Signature")
            .expect("X-Slack-Signature header is missing")
            .to_str()
            .unwrap();

    if format!("v0={}", result) != expected_signature {
        //log
        tracing::error!("Invalid signature");
        return (StatusCode::UNAUTHORIZED, "Invalid signature").into_response();
    }

    //log
    tracing::info!("success");
    *request.body_mut() = body_copy;
    let response = next.run(request).await;
    response
}

async fn root() -> Json<Value> {
    Json(json!({ "msg": "I am GET /" }))
}

async fn get_slack_events() -> Json<Value> {
    Json(json!({ "msg": "I am GET /" }))
}

async fn post_slack_events(request: Request<lambda_http::Body>) -> Json<Value> {
    // read body json
    let body = request.body();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let body_json: Value = serde_json::from_str(&body_str).unwrap();

    let typ = body_json["type"].as_str().unwrap();

    return match typ {
        "url_verification" => {
            let challenge = body_json["challenge"].as_str().unwrap();
            Json(json!({ "challenge": challenge }))
        }
        _ => Json(json!({ "msg": "I am POST /slack-events" })),
    };
}

async fn post_foo_name(Path(name): Path<String>) -> Json<Value> {
    Json(json!({ "msg": format!("I am POST /foo/:name, name={name}") }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // required to enable CloudWatch error logging by the runtime
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    let app = Router::new()
        .route("/", get(root))
        .route(
            "/slack-events",
            get(get_slack_events)
                .post(post_slack_events)
                .route_layer(middleware::from_fn(validate_slack_signature)),
        )
        .route("/foo/:name", post(post_foo_name));

    run(app).await
}
