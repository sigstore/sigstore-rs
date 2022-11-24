//
// Copyright 2022 The Sigstore Authors.
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

//! This module defines different kinds of payload to be signed
//! in cosign. Now it supports:
//! * `SimpleSigning`: Refer to
//! <https://github.com/containers/image/blob/a5061e5a5f00333ea3a92e7103effd11c6e2f51d/docs/containers-signature.5.md#json-data-format>

pub mod simple_signing;
pub use simple_signing::SimpleSigning;
