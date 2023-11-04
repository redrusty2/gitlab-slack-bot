use axum::{
    debug_handler,
    extract::{FromRequest, State},
    http::{HeaderValue, Request},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use gitlab_slack_bot::{state::AppState, gitlab};
use hmac::{Hmac, Mac};
use hyper::{
    header::{AUTHORIZATION, CONTENT_TYPE},
    HeaderMap, StatusCode,
};
use lambda_http::{run, Error};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Arc;

use gitlab_slack_bot::gitlab::{extract_gitlab_url_params, get_gitlab_mr, validate_gitlab_token};

type HmacSha256 = Hmac<Sha256>;

const SLACK_POST_MESSAGE_URL: &str = "https://slack.com/api/chat.postMessage";
const SLACK_SIGNATURE_VERSION: &str = "v0";
static SLACK_SIGNING_SECRET: Lazy<String> =
    Lazy::new(|| std::env::var("SLACK_SIGNING_SECRET").expect("SLACK_SIGNING_SECRET is not set."));
static SLACK_OAUTH_TOKEN: Lazy<String> =
    Lazy::new(|| std::env::var("SLACK_OAUTH_TOKEN").expect("SLACK_OAUTH_TOKEN is not set."));

const GITLAB_DOMAIN: &str = "gitlab.com";
static GITLAB_SECRET_TOKEN: Lazy<String> =
    Lazy::new(|| std::env::var("GITLAB_SECRET_TOKEN").expect("GITLAB_SECRET_TOKEN is not set."));
static GITLAB_API_TOKEN: Lazy<String> =
    Lazy::new(|| std::env::var("GITLAB_API_TOKEN").expect("GITLAB_API_TOKEN is not set."));

async fn validate_slack_signature(
    mut request: Request<lambda_http::Body>,
    next: Next<lambda_http::Body>,
) -> Response {
    let timestamp = &request
        .headers()
        .get("X-Slack-Request-Timestamp")
        .expect("X-Slack-Request-Timestamp header is missing")
        .to_owned();
    let timestamp_str = timestamp.to_str().unwrap();

    let body_str = String::from_utf8(request.body_mut().to_vec()).unwrap();

    let base_string = format!("{}:{}:{}", SLACK_SIGNATURE_VERSION, timestamp_str, body_str);
    let mut mac = HmacSha256::new_from_slice(SLACK_SIGNING_SECRET.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(base_string.as_bytes());
    let generated_signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let slack_signature = request
        .headers()
        .get("X-Slack-Signature")
        .expect("X-Slack-Signature header is missing")
        .to_str()
        .unwrap();

    if format!("{}={}", SLACK_SIGNATURE_VERSION, generated_signature) != slack_signature {
        //log
        tracing::error!("Invalid signature");
        return (StatusCode::UNAUTHORIZED, "Invalid signature").into_response();
    }

    //log
    tracing::info!("Signature is valid");
    let response = next.run(request).await;
    response
}

async fn hello() -> String {
    "Hello".to_string()
}

async fn post_slack_events(
    State(state): State<Arc<AppState>>,
    Json(body_json): Json<Value>,
) -> Response {
    // read body json
    // let body = request.body();
    // let body_str = String::from_utf8(body.to_vec()).unwrap();
    // let body_json: Value = serde_json::from_str(&body_str).unwrap();

    // log body
    tracing::info!("body: {:?}", body_json);

    let typ = body_json["type"].as_str().unwrap();

    return match typ {
        "url_verification" => {
            tracing::info!("Slack url_verification");
            let challenge = body_json["challenge"].as_str().unwrap();
            Json(json!({ "challenge": challenge })).into_response()
        }
        "event_callback" => match body_json["event"]["type"].as_str().unwrap() {
            "link_shared" => {
                tracing::info!("Slack link_shared");

                let url_params = extract_gitlab_url_params(
                    &body_json["event"]["links"][0]["url"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                );
                let (mr, approvers) = get_gitlab_mr(state.clone(), &url_params).await;

                let body = json!({
                    "channel": body_json["event"]["channel"],
                    "text": format!("*{}* - {} - {} - {} - {} - {} - {}",
                        mr.title,
                        mr.state,
                        mr.draft,
                        mr.assignee.map(|a| a.name).unwrap_or("None".to_string()),
                        mr.source_branch,
                        mr.target_branch,
                        approvers.iter().map(|a| a.username.clone()).collect::<Vec<String>>().join(", ")
                    ),
                });

                let write_res = state
                    .http_client
                    .post(SLACK_POST_MESSAGE_URL)
                    .headers(state.slack_api_headers.clone())
                    .json(&body)
                    .send()
                    .await
                    .unwrap();

                //log
                tracing::info!("slack response: {:?}", write_res);
                tracing::info!("slack response body: {:?}", write_res.text().await);

                Json(json!({})).into_response()
            }
            _event_type => {
                tracing::info!("Unknown event_callback type: {}", _event_type);
                (StatusCode::BAD_REQUEST, "Unknown event_callback type").into_response()
            }
        },
        _event_type => {
            tracing::info!("Unknown event type: {}", _event_type);
            (StatusCode::BAD_REQUEST, "Unknown event type").into_response()
        }
    };
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

    let mut slack_api_headers = HeaderMap::new();
    slack_api_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    slack_api_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(format!("Bearer {}", SLACK_OAUTH_TOKEN.as_str()).as_str()).unwrap(),
    );

    let mut gitlab_api_headers = HeaderMap::new();
    gitlab_api_headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(format!("Bearer {}", GITLAB_API_TOKEN.as_str()).as_str()).unwrap(),
    );

    let shared_config = aws_config::from_env().load().await;
    let db_client = aws_sdk_dynamodb::Client::new(&shared_config);

    let app_state = Arc::new(AppState {
        http_client: Client::new(),
        slack_api_headers,
        gitlab_api_headers,
        gitlab_api_token: GITLAB_API_TOKEN.as_str().to_string(),
        gitlab_secret_token: GITLAB_SECRET_TOKEN.as_str().to_string(),
        db_client,
    });

    let app = Router::new()
        .route(
            "/slack-events",
            post(post_slack_events).route_layer(middleware::from_fn(validate_slack_signature)),
        )
        .route(
            "/gitlab-events",
            post(gitlab::handle_event).route_layer(middleware::from_fn_with_state(app_state.clone(), validate_gitlab_token)),
        )
        .with_state(app_state)
        .route("/", get(hello));

    run(app).await
}
