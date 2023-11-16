// Copyright 2023 The Sigstore Authors.
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

//! Useful types for Sigstore bundles.

use std::fmt::Display;

pub use sigstore_protobuf_specs::Bundle;

// Known Sigstore bundle media types.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    _Bundle0_1,
    Bundle0_2,
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self {
            Version::_Bundle0_1 => "application/vnd.dev.sigstore.bundle+json;version=0.1",
            Version::Bundle0_2 => "application/vnd.dev.sigstore.bundle+json;version=0.2",
        })
    }
}
