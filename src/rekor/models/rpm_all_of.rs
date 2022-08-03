/*
 * Rekor
 *
 * Rekor is a cryptographically secure, immutable transparency log for signed software releases.
 *
 * The version of the OpenAPI document: 0.0.1
 *
 * Generated by: https://openapi-generator.tech
 */
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct RpmAllOf {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "spec")]
    pub spec: serde_json::Value,
}

impl RpmAllOf {
    pub fn new(api_version: String, spec: serde_json::Value) -> RpmAllOf {
        RpmAllOf { api_version, spec }
    }
}