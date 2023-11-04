use hyper::HeaderMap;
use reqwest::Client;

pub struct AppState {
    pub http_client: Client,
    pub slack_api_headers: HeaderMap,
    pub gitlab_api_headers: HeaderMap,
    pub gitlab_api_token: String,
}
