//! This module provides a series of Rust Struct that implementation
//! the Container signature format described
//! [here](https://github.com/containers/image/blob/a5061e5a5f00333ea3a92e7103effd11c6e2f51d/docs/containers-signature.5.md#json-data-format).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, fmt};
use tracing::{debug, error, info};

#[derive(Serialize, Deserialize, Debug)]
pub struct SimpleSigning {
    pub critical: Critical,
    pub optional: Option<Optional>,
}

impl fmt::Display for SimpleSigning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl SimpleSigning {
    pub fn satisfies_annotations(&self, annotations: &HashMap<String, String>) -> bool {
        if annotations.is_empty() {
            debug!("no annotations have been provided -> returning true");
            return true;
        }

        match self.optional {
            Some(_) => self
                .optional
                .clone()
                .unwrap()
                .satisfies_annotations(annotations),
            None => {
                info!(
                    simple_signing=?self,
                    ?annotations,
                    "annotations not satisfied because `optional` attribute is None"
                );
                false
            }
        }
    }
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Optional {
    pub creator: Option<String>,
    pub timestamp: Option<i64>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Optional {
    pub fn satisfies_annotations(&self, annotations: &HashMap<String, String>) -> bool {
        if self.extra.is_empty() {
            info!(?annotations, "Annotations are not satisfied, no annotations are part of the Simple Signing object");
            return false;
        }

        for (req_key, req_val) in annotations {
            match self.extra.get(req_key) {
                Some(curr_val) => match curr_val {
                    serde_json::Value::String(s) => {
                        if req_val != s {
                            info!(
                                annotation = ?req_key,
                                expected_value = ?req_val,
                                current_value = ?s,
                                "Annotation not satisfied"
                            );
                            return false;
                        }
                    }
                    serde_json::Value::Number(n) => {
                        let curr_val = n.to_string();
                        if req_val != &curr_val {
                            info!(
                                annotation = ?req_key,
                                expected_value = ?req_val,
                                current_value = ?n,
                                "Annotation not satisfied"
                            );
                            return false;
                        }
                    }
                    serde_json::Value::Bool(b) => {
                        let curr_val = if *b { "true" } else { "false" };
                        if req_val != curr_val {
                            info!(
                                annotation = ?req_key,
                                expected_value = ?req_val,
                                current_value = ?curr_val,
                                "Annotation not satisfied"
                            );
                            return false;
                        }
                    }
                    _ => {
                        error!(
                            annotation = ?req_key,
                            expected_value = ?req_val,
                            current_value = ?curr_val.to_string(),
                            "Annotation type not handled"
                        );
                        return false;
                    }
                },
                None => {
                    info!(
                            missing_annotation = ?req_key,
                            layer_annotations= ?self.extra,
                            "Annotation not satisfied");
                    return false;
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn simple_signing_does_not_satisfy_annotations_when_optional_is_none() {
        let ss_json = json!({
            "critical": {
                "type": "type_foo",
                "image": {
                    "docker-manifest-digest": "sha256:something"
                },
                "identity": {
                    "docker-reference": "registry.foo.bar/busybox"
                }
            }
        });
        let ss: SimpleSigning = serde_json::from_value(ss_json).unwrap();

        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert(String::from("env"), String::from("prod"));

        assert!(!ss.satisfies_annotations(&annotations));
    }

    #[test]
    fn simple_signing_satisfies_empty_annotations_even_when_optional_is_none() {
        let ss_json = json!({
            "critical": {
                "type": "type_foo",
                "image": {
                    "docker-manifest-digest": "sha256:something"
                },
                "identity": {
                    "docker-reference": "registry.foo.bar/busybox"
                }
            }
        });
        let ss: SimpleSigning = serde_json::from_value(ss_json).unwrap();
        let annotations: HashMap<String, String> = HashMap::new();

        assert!(ss.satisfies_annotations(&annotations));
    }

    #[test]
    fn optional_has_all_the_required_annotations() {
        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert(String::from("env"), String::from("prod"));
        annotations.insert(String::from("number"), String::from("1"));
        annotations.insert(String::from("bool"), String::from("true"));

        let optional_json = json!({
            "env": "prod",
            "number": 1,
            "bool": true
        });
        let optional: Optional = serde_json::from_value(optional_json).unwrap();

        assert!(optional.satisfies_annotations(&annotations));
    }

    #[test]
    fn optional_does_not_satisfy_annotations_because_one_annotation_is_missing() {
        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert(String::from("env"), String::from("prod"));
        annotations.insert(String::from("owner"), String::from("flavio"));

        let optional_json = json!({
            "owner": "flavio",
            "team": "devops"
        });
        let optional: Optional = serde_json::from_value(optional_json).unwrap();

        assert!(!optional.satisfies_annotations(&annotations));
    }

    #[test]
    fn optional_does_not_satisfy_annotations_because_one_annotation_has_different_value() {
        let mut annotations: HashMap<String, String> = HashMap::new();
        annotations.insert(String::from("env"), String::from("prod"));
        annotations.insert(String::from("owner"), String::from("flavio"));

        let optional_json = json!({
            "env": "staging",
            "owner": "flavio",
            "team": "devops"
        });
        let optional: Optional = serde_json::from_value(optional_json).unwrap();

        assert!(!optional.satisfies_annotations(&annotations));
    }

    #[test]
    fn optional_satisfies_annotations_when_no_annotation_is_provided() {
        let annotations: HashMap<String, String> = HashMap::new();

        let optional_json = json!({
            "env": "prod",
            "owner": "flavio",
            "team": "devops"
        });
        let optional: Optional = serde_json::from_value(optional_json).unwrap();

        assert!(optional.satisfies_annotations(&annotations));
    }
}
