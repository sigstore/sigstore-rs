#!/usr/bin/env python3

# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# script checks the src directory for instances of unwrap / panic
# legimate uses can be overridden by commenting: //#[allow_ci]

import os

banned = ["unwrap(", "panic!(", "unsafe"]

for root, dirs, files in os.walk("src", topdown=False):
   for name in files:
      with open(os.path.join(root, name)) as src_file:
            for line_no, line in enumerate(src_file):
                for b in banned:
                    if b not in line or "//#[allow_ci]" in line:
                        continue
                    failed = True
                    print("File %s on line number: %s calls banned function: %s)" % (os.path.join(root, name), line_no + 1, b))
                continue
exit(failed)
