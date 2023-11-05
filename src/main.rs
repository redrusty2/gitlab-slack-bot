use aws_sdk_dynamodb::types::AttributeValue;
use axum::{
    debug_handler,
    extract::{FromRequest, State},
    http::{HeaderValue, Request},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use gitlab_slack_bot::{
    gitlab::{self, create_status_message, GitlabUrlParams},
    state::AppState,
};
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

use gitlab_slack_bot::gitlab::{
    extract_gitlab_url_params, get_gitlab_mr_from_url, validate_gitlab_token,
};

type HmacSha256 = Hmac<Sha256>;

const SLACK_POST_MESSAGE_URL: &str = "https://slack.com/api/chat.postMessage";
const SLACK_DELETE_MESSAGE_URL: &str = "https://slack.com/api/chat.delete";
const SLACK_UPDATE_MESSAGE_URL: &str = "https://slack.com/api/chat.update";
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

                let link = body_json["event"]["links"][0]["url"]
                    .as_str()
                    .unwrap()
                    .to_string();

                //if the end of the link is #posted_by_bot, ignore it
                if link.ends_with("#posted_by_bot") {
                    return Json(json!({})).into_response();
                }

                let url_params = extract_gitlab_url_params(&link);
                let (mr, approvers) = get_gitlab_mr_from_url(state.clone(), url_params).await;
                let blocks = create_status_message(&mr, &approvers);
                let body = json!({
                    "channel": body_json["event"]["channel"],
                    "blocks": blocks,
                });

                let write_res = state
                    .http_client
                    .post(SLACK_POST_MESSAGE_URL)
                    .headers(state.slack_api_headers.clone())
                    .json(&body)
                    .send()
                    .await
                    .unwrap();

                // TODO only have one message exist per merge request, delete old ones
                // store message ts in db
                let body: Value = write_res.json().await.unwrap();
                tracing::info!("slack response body: {:?}", body);
                let ts = body["ts"].as_str().unwrap();
                let channel = body_json["event"]["channel"].as_str().unwrap();

                let query_request = state
                    .db_client
                    .query()
                    .table_name(state.db_slack_messages_table_name.clone())
                    .key_condition_expression("merge_request_id = :merge_request_id")
                    .expression_attribute_values(
                        ":merge_request_id".to_string(),
                        AttributeValue::S(mr.id.to_string()),
                    );

                tracing::info!("dynamodb query: {:?}", query_request);

                let query_res = query_request.send().await;

                // delete old slack message
                let items = query_res.unwrap().items.unwrap();
                if items.len() > 0 {
                    let body = json!({
                        "channel": body_json["event"]["channel"],
                        "ts": items[0]["message_ts"].as_s().unwrap(),
                    });

                    let delete_res = state
                        .http_client
                        .post(SLACK_DELETE_MESSAGE_URL)
                        .headers(state.slack_api_headers.clone())
                        .json(&body)
                        .send()
                        .await
                        .unwrap();

                    let body: Value = delete_res.json().await.unwrap();

                    tracing::info!("slack delete response body: {:?}", body);
                }

                let mut item = std::collections::HashMap::new();
                item.insert(
                    "merge_request_id".to_string(),
                    AttributeValue::S(mr.id.to_string()),
                );
                item.insert("message_ts".to_string(), AttributeValue::S(ts.to_string()));
                item.insert(
                    "channel".to_string(),
                    AttributeValue::S(channel.to_string()),
                );

                let put_request = state
                    .db_client
                    .put_item()
                    .table_name(state.db_slack_messages_table_name.clone())
                    .set_item(Some(item));

                let res = put_request.send().await;

                tracing::info!("dynamodb response: {:?}", res);

                Json(json!({})).into_response()
            }
            _event_type => {
                tracing::info!("Unknown event_callback type: {}", _event_type);
                (StatusCode::OK, "Unknown event_callback type").into_response()
            }
        },
        _event_type => {
            tracing::info!("Unknown event type: {}", _event_type);
            (StatusCode::OK, "Unknown event type").into_response()
        }
    };
}

async fn update_slack_messages(
    state: Arc<AppState>,
    merge_request_id: i64,
    merge_request_iid: i64,
    project_with_namespace: String,
) {
    let query_request = state
        .db_client
        .query()
        .table_name(state.db_slack_messages_table_name.clone())
        .key_condition_expression("merge_request_id = :merge_request_id")
        .expression_attribute_values(
            ":merge_request_id".to_string(),
            AttributeValue::S(merge_request_id.to_string()),
        );

    tracing::info!("dynamodb query: {:?}", query_request);

    let res = query_request.send().await;

    tracing::info!("dynamodb response: {:?}", res);

    let messages = res
        .unwrap()
        .items
        .unwrap()
        .iter()
        .map(|item| {
            let message_ts = item
                .get("message_ts")
                .unwrap()
                .as_s()
                .as_ref()
                .unwrap()
                .to_string();
            let channel = item
                .get("channel")
                .unwrap()
                .as_s()
                .as_ref()
                .unwrap()
                .to_string();

            (message_ts, channel)
        })
        .collect::<Vec<(String, String)>>();

    if messages.len() == 0 {
        return;
    }

    let url_params = GitlabUrlParams {
        merge_request_iid: merge_request_iid.to_string(),
        project_with_namespace,
    };

    let (mr, approvers) = get_gitlab_mr_from_url(state.clone(), url_params).await;
    let blocks = create_status_message(&mr, &approvers);
    for message in messages {
        let body = json!({
            "channel": message.1,
            "blocks": blocks,
            "ts": message.0
        });

        let write_res = state
            .http_client
            .post(SLACK_UPDATE_MESSAGE_URL)
            .headers(state.slack_api_headers.clone())
            .json(&body)
            .send()
            .await
            .unwrap();

        let body: Value = write_res.json().await.unwrap();
        tracing::info!("slack response body: {:?}", body);
    }
}

async fn handle_gitlab_event(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Response {
    tracing::info!("gitlab event body: {:?}", body);

    let event_type = body["event_type"].as_str().unwrap();
    let object_kind = body["object_kind"].as_str().unwrap();

    if event_type != "merge_request" || object_kind != "merge_request" {
        tracing::info!("Not a merge request event");
        return StatusCode::OK.into_response();
    }

    let action = body["object_attributes"]["action"].as_str().unwrap();

    let merge_request_iid = body["object_attributes"]["iid"].as_i64().unwrap();
    let merge_request_id = body["object_attributes"]["id"].as_i64().unwrap();
    let project_with_namespace = body["project"]["path_with_namespace"]
        .as_str()
        .unwrap()
        .to_string();

    if action == "approved" {
        tracing::info!("Gitlab merge request approved");
        gitlab::handle_approved_event(state.clone(), &body).await;
    } else if action == "unapproved" {
        tracing::info!("unapproved");
        gitlab::handle_unapproved_event(state.clone(), &body).await;
    }

    let relevant_actions = vec![
        "approved",
        "unapproved",
        "update",
        "reopen",
        "close",
        "merge",
    ];

    let relevant_changes = vec!["title", "assignee_id", "assignee_ids"];

    if relevant_actions.contains(&action) && !relevant_changes.contains(&action) {
        tracing::info!("Gitlab merge request action: {}", action);
        update_slack_messages(
            state.clone(),
            merge_request_id,
            merge_request_iid,
            project_with_namespace,
        )
        .await;
    }

    StatusCode::OK.into_response()
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
        db_approvers_table_name: "gitlab-merge-request-approvers".to_string(),
        db_slack_messages_table_name: "gitlab-merge-request-slack-messages".to_string(),
    });

    let app = Router::new()
        .route(
            "/slack-events",
            post(post_slack_events).route_layer(middleware::from_fn(validate_slack_signature)),
        )
        .route(
            "/gitlab-events",
            post(handle_gitlab_event).route_layer(middleware::from_fn_with_state(
                app_state.clone(),
                validate_gitlab_token,
            )),
        )
        .with_state(app_state)
        .route("/", get(hello));

    run(app).await
}
