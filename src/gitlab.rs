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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::sync::Arc;
use url::Url;

use crate::state::AppState;

pub struct GitlabUrlParams {
    pub project_with_namespace: String,
    pub merge_request_iid: String,
}

#[derive(Deserialize, Debug)]
pub struct Project {
    pub name: String,
    pub web_url: String,
}

#[derive(Deserialize, Debug)]
pub struct MergeStatus {
    pub title: String,
    pub state: String,
    pub draft: bool,
    pub assignee: Option<Assignee>,
    pub source_branch: String,
    pub target_branch: String,
    pub id: i64,
    pub iid: i64,
    pub web_url: String,
}

#[derive(Deserialize)]
pub struct PipelineStatus {
    pub status: String,
}

#[derive(Deserialize, Debug)]
pub struct Assignee {
    pub name: String,
}

#[derive(Deserialize, Debug)]
pub struct Approver {
    pub username: String,
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
    url_params: &GitlabUrlParams,
) -> (MergeStatus, Vec<Approver>) {
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
            let status: MergeStatus = serde_json::from_str(&body).unwrap();
            let approvers = get_approvers(status.id, State(state.clone()));
            (status, approvers.await)
        }
        Err(e) => {
            tracing::error!("gitlab response error: {:?}", e);
            (
                MergeStatus {
                    title: "Error".to_string(),
                    state: "Error".to_string(),
                    draft: false,
                    assignee: None,
                    source_branch: "Error".to_string(),
                    target_branch: "Error".to_string(),
                    id: -1,
                    iid: -1,
                    web_url: "Error".to_string(),
                },
                vec![],
            )
        }
    }
}

pub async fn get_gitlab_project_from_url(
    state: Arc<AppState>,
    url_params: &GitlabUrlParams,
) -> Project {
    let gl_res = state
        .http_client
        .get(format!(
            "https://gitlab.com/api/v4/projects/{}",
            url_params.project_with_namespace.replace("/", "%2F"),
        ))
        .headers(state.gitlab_api_headers.clone())
        .send()
        .await;

    tracing::info!("gitlab response: {:?}", gl_res);

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
            serde_json::from_str(&body).unwrap()
        }
        Err(e) => {
            tracing::error!("gitlab response error: {:?}", e);
            Project {
                name: "Error".to_string(),
                web_url: "Error".to_string(),
            }
        }
    }
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

pub async fn handle_approved_event(state: Arc<AppState>, body: &Value) {
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
    item.insert(
        "approver_name".to_string(),
        AttributeValue::S(body["user"]["name"].as_str().unwrap().to_string()),
    );

    let put_request = state
        .db_client
        .put_item()
        .table_name(state.db_approvers_table_name.clone())
        .set_item(Some(item));

    let res = put_request.send().await;

    tracing::info!("dynamodb response: {:?}", res);
}

pub async fn handle_unapproved_event(state: Arc<AppState>, body: &Value) {
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
            name: item   
                .get("approver_name")
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

#[derive(Serialize, Deserialize)]
struct MarkdownElement {
    #[serde(rename = "type")]
    element_type: String,
    text: String,
}

#[derive(Serialize, Deserialize)]
pub struct ContextBlock {
    #[serde(rename = "type")]
    block_type: String,
    elements: Vec<MarkdownElement>,
}

pub fn create_status_message_blocks(
    merge_status: &MergeStatus,
    approvers: &Vec<Approver>,
    project: &Project,
) -> Vec<ContextBlock> {
    let status = match merge_status.state.as_str() {
        "opened" => {
            if merge_status.draft {
                (":white_circle:", "Draft")
            } else {
                (":large_green_circle:", "Open")
            }
        }
        "closed" => (":red_circle:", "Closed"),
        "merged" => (":large_blue_circle:", "Merged"),
        _ => ("", "Unknown"),
    };

    let strikethrough = if merge_status.state != "opened" {
        "~"
    } else {
        ""
    };

    let mut context_block = ContextBlock {
        block_type: "context".to_string(),
        elements: vec![MarkdownElement {
            element_type: "mrkdwn".to_string(),
            text: format!(
                "{}{} _{}_   <{}#posted_by_bot|{}> | <{}#posted_by_bot|{}>   _*Assignee:*_ {}{}",
                strikethrough,
                status.0,
                status.1,
                project.web_url,
                project.name,
                merge_status.web_url,
                merge_status.title,
                merge_status.assignee.as_ref().unwrap().name,
                strikethrough
            ),
        }],
    };

    if !approvers.is_empty() {
        context_block.elements.push(MarkdownElement {
            element_type: "mrkdwn".to_string(),
            text: format!(
                "{}:white_check_mark: _*Approved:*_ {}{}",
                strikethrough,
                approvers
                    .iter()
                    .map(|a| a.username.clone())
                    .collect::<Vec<String>>()
                    .join(", "),
                strikethrough
            ),
        })
    };

    vec![context_block]
}

pub fn create_status_message_text(
    merge_status: &MergeStatus,
    approvers: &Vec<Approver>,
    project: &Project,
) -> String {
    let status = match merge_status.state.as_str() {
        "opened" => {
            if merge_status.draft {
                (":white_circle:", "Draft")
            } else {
                (":large_green_circle:", "Open")
            }
        }
        "closed" => (":red_circle:", "Closed"),
        "merged" => (":large_blue_circle:", "Merged"),
        _ => ("", "Unknown"),
    };

    let approvers_part = if !approvers.is_empty() {
        format!(
            "   _*Approvals:*_ {}",
            approvers
                .iter()
                .map(|a| a.name.clone())
                .collect::<Vec<String>>()
                .join(", "),
        )
    } else {
        "".to_string()
    };

    let approved_part = if !approvers.is_empty() {
            ":white_check_mark: _*Approved*_   ".to_string()
    } else {
        "".to_string()
    };

    let mut text = format!(
        "{}{} _{}_   <{}#posted_by_bot|{}> | <{}#posted_by_bot|{}>   _*Assignee:*_ {}{}",
        approved_part,
        status.0,
        status.1,
        project.web_url,
        project.name,
        merge_status.web_url,
        merge_status.title,
        merge_status.assignee.as_ref().unwrap().name,
        approvers_part,
    );

    if merge_status.state != "opened" {
        text = format!("~{}~", text);
    };

    text 
}
