use hyper::HeaderMap;
use reqwest::Client;
use aws_sdk_dynamodb::Client as DynamoDbClient;

pub struct AppState {
    pub http_client: Client,
    pub slack_api_headers: HeaderMap,
    pub gitlab_api_headers: HeaderMap,
    pub gitlab_api_token: String,
    pub gitlab_secret_token: String,
    pub db_client: DynamoDbClient
}
