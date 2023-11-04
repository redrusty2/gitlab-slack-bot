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
use url::Url;

use crate::state::AppState;

pub struct GitlabUrlParams {
    pub project_with_namespace: String,
    pub merge_request_iid: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct MergeRequestStatus {
    pub title: String,
    pub state: String,
    pub draft: bool,
    pub assignee: Option<Assignee>,
    pub source_branch: String,
    pub target_branch: String,
    pub approvers: Option<Vec<Approver>>,
    pub id: i64,
}

#[derive(serde::Deserialize)]
pub struct PipelineStatus {
    pub status: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct Assignee {
    pub name: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct Approver {
    pub username: String,
}

pub async fn validate_gitlab_token(
    State(state): State<Arc<AppState>>,
    request: Request<lambda_http::Body>,
    next: Next<lambda_http::Body>,
) -> Response {
    let received_token = &request
        .headers()
        .get("X-Gitlab-Token")
        .expect("X-Gitlab-Token header is missing")
        .to_owned();
    let received_token_str = received_token.to_str().unwrap();

    if state.gitlab_secret_token != received_token_str {
        tracing::error!("Invalid token");
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    //log
    tracing::info!("Token is valid");
    let response = next.run(request).await;
    response
}

pub async fn get_gitlab_mr_from_url(
    state: Arc<AppState>,
    url_params: GitlabUrlParams,
) -> (MergeRequestStatus, Vec<Approver>) {
    let gl_res = state
        .http_client
        .get(format!(
            "https://gitlab.com/api/v4/projects/{}/merge_requests/{}",
            url_params.project_with_namespace.replace("/", "%2F"),
            url_params.merge_request_iid
        ))
        .headers(state.gitlab_api_headers.clone())
        .send()
        .await;

    tracing::info!("gitlab response: {:?}", gl_res);
    // tracing::info!("gitlab response body: {:?}", write_res.text().await);
    //

    match gl_res {
        Ok(res) => {
            let body = res
                .text()
                .await
                .map_err(|e| {
                    tracing::error!("gitlab response error: {:?}", e);
                    e
                })
                .unwrap();
            tracing::info!("gitlab response body: {:?}", body);
            let status: MergeRequestStatus = serde_json::from_str(&body).unwrap();
            let approvers = get_approvers(status.id, State(state.clone()));
            (status, approvers.await)
        }
        Err(e) => {
            tracing::error!("gitlab response error: {:?}", e);
            (
                MergeRequestStatus {
                    title: "Error".to_string(),
                    state: "Error".to_string(),
                    draft: false,
                    assignee: None,
                    source_branch: "Error".to_string(),
                    target_branch: "Error".to_string(),
                    approvers: None,
                    id: -1,
                },
                vec![],
            )
        }
    }
    // deserialize merge status from body
    // let body = write_res.json().await.unwrap();
    //
    // tracing::info!("gitlab response body: {:?}", body);
    // body
}

pub fn extract_gitlab_url_params(url_str: &String) -> GitlabUrlParams {
    let url = Url::parse(url_str).unwrap();

    let mut path_segments = url
        .path_segments()
        .expect("Cannot extract path segments")
        .peekable();

    // TODO check domain
    //
    let namespace = path_segments.next().unwrap_or("");
    let project = path_segments.next().unwrap_or("");

    // TODO check this is what we expect
    // Skip '-/merge_requests/'
    path_segments.next();
    path_segments.next();

    let merge_request_iid = path_segments.next().unwrap_or("");

    //log
    tracing::info!(
        "namespace: {}, project: {}, merge_request_iid: {}",
        namespace,
        project,
        merge_request_iid
    );

    GitlabUrlParams {
        project_with_namespace: format!("{}%2F{}", namespace, project),
        merge_request_iid: merge_request_iid.to_string(),
    }
}

pub async fn handle_approved_event(state: Arc<AppState>, body: Value) {
    let mut item = std::collections::HashMap::new();
    item.insert(
        "merge_request_id".to_string(),
        AttributeValue::S(
            body["object_attributes"]["id"]
                .as_i64()
                .unwrap()
                .to_string(),
        ),
    );
    item.insert(
        "approver_username".to_string(),
        AttributeValue::S(body["user"]["username"].as_str().unwrap().to_string()),
    );

    let put_request = state
        .db_client
        .put_item()
        .table_name(state.db_approvers_table_name.clone())
        .set_item(Some(item));

    let res = put_request.send().await;

    tracing::info!("dynamodb response: {:?}", res);
}

pub async fn handle_unapproved_event(state: Arc<AppState>, body: Value) {
    let mut key = std::collections::HashMap::new();
    key.insert(
        "merge_request_id".to_string(),
        AttributeValue::S(
            body["object_attributes"]["id"]
                .as_i64()
                .unwrap()
                .to_string(),
        ),
    );
    key.insert(
        "approver_username".to_string(),
        AttributeValue::S(body["user"]["username"].as_str().unwrap().to_string()),
    );

    let delete_request = state
        .db_client
        .delete_item()
        .table_name(state.db_approvers_table_name.clone())
        .set_key(Some(key));

    let res = delete_request.send().await;

    tracing::info!("dynamodb response: {:?}", res);
}

pub async fn get_approvers(
    merge_request_id: i64,
    State(state): State<Arc<AppState>>,
) -> Vec<Approver> {
    let mut key = std::collections::HashMap::new();
    key.insert(
        "merge_request_id".to_string(),
        AttributeValue::S(merge_request_id.to_string()),
    );

    let query_request = state
        .db_client
        .query()
        .table_name(state.db_approvers_table_name.clone())
        .key_condition_expression("merge_request_id = :merge_request_id")
        .expression_attribute_values(
            ":merge_request_id",
            AttributeValue::S(merge_request_id.to_string()),
        );

    let res = query_request.send().await;

    tracing::info!("dynamodb response: {:?}", res);

    let items = res.unwrap().items.unwrap();

    let mut approvers = Vec::new();

    for item in items {
        let approver = Approver {
            username: item
                .get("approver_username")
                .unwrap()
                .as_s()
                .as_ref()
                .unwrap()
                .to_string(),
        };

        approvers.push(approver);
    }

    approvers
}
