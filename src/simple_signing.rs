//! This module provides a series of Rust Struct that implementation
//! the Container signature format described
//! [here](https://github.com/containers/image/blob/a5061e5a5f00333ea3a92e7103effd11c6e2f51d/docs/containers-signature.5.md#json-data-format).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub struct SimpleSigning {
    pub critical: Critical,
    pub optional: Option<Optional>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Critical {
    #[serde(rename = "type")]
    //TODO: should we validate the contents of this attribute to ensure it's "cosign container image signature"?
    pub type_name: String,
    pub image: Image,
    pub identity: Identity,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Image {
    pub docker_manifest_digest: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Identity {
    pub docker_reference: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Optional {
    pub creator: Option<String>,
    pub timestamp: Option<i64>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
