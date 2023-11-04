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
    pub namespace: String,
    pub project: String,
    pub merge_request_id: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct MergeRequestStatus {
    pub title: String,
    pub state: String,
    pub draft: bool,
    pub assignee: Option<Assignee>,
    pub source_branch: String,
    pub target_branch: String,
}

#[derive(serde::Deserialize)]
pub struct PipelineStatus {
    pub status: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct Assignee {
    pub name: String
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

    if state.gitlab_api_token != received_token_str {
        tracing::error!("Invalid token");
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    //log
    tracing::info!("Token is valid");
    let response = next.run(request).await;
    response
}

pub async fn get_gitlab_mr(state: Arc<AppState>, url_params: &GitlabUrlParams) -> MergeRequestStatus {
    let write_res = state
        .http_client
        .get(format!(
            "https://gitlab.com/api/v4/projects/{}%2F{}/merge_requests/{}",
            url_params.namespace, url_params.project, url_params.merge_request_id
        ))
        .headers(state.gitlab_api_headers.clone())
        .send()
        .await;

    tracing::info!("gitlab response: {:?}", write_res);
    // tracing::info!("gitlab response body: {:?}", write_res.text().await);

    match write_res {
        Ok(res) => {
            let body = res.text().await.map_err(|e| {
                tracing::error!("gitlab response error: {:?}", e);
                e
            }).unwrap(); 
            tracing::info!("gitlab response body: {:?}", body);
            serde_json::from_str(&body).unwrap()
        }
        Err(e) => {
            tracing::error!("gitlab response error: {:?}", e);
            MergeRequestStatus {
                title: "Error".to_string(),
                state: "Error".to_string(),
                draft: false,
                assignee: None,
                source_branch: "Error".to_string(),
                target_branch: "Error".to_string(),
            }
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
        namespace: namespace.to_string(),
        project: project.to_string(),
        merge_request_id: merge_request_iid.to_string(),
    }
}
