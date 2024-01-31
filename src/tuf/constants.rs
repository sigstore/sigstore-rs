//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::Path;
use tough::TargetName;

pub(crate) const SIGSTORE_METADATA_BASE: &str = "https://tuf-repo-cdn.sigstore.dev";
pub(crate) const SIGSTORE_TARGET_BASE: &str = "https://tuf-repo-cdn.sigstore.dev/targets";

macro_rules! tuf_resource {
    ($path:literal) => {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/trust_root/", $path))
    };
}

pub(crate) const SIGSTORE_ROOT: &Path = tuf_resource!("prod/root.json");
pub(crate) const SIGSTORE_TRUST_BUNDLE: &Path = tuf_resource!("prod/trusted_root.json");
