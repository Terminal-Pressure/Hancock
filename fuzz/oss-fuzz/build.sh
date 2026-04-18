#!/bin/bash -eu
# Copyright 2025 Google LLC
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
#
################################################################################

# OSS-Fuzz build script for Hancock

# Install project dependencies so fuzz targets can import modules
pip3 install -r "$SRC/hancock/requirements.txt"
pip3 install atheris

# Ensure the project root is on PYTHONPATH so fuzz targets can resolve imports
export PYTHONPATH="$SRC/hancock${PYTHONPATH:+:$PYTHONPATH}"

# Compile each fuzz target using the OSS-Fuzz Python helper
FUZZ_DIR="$SRC/hancock/fuzz"

for fuzzer in "$FUZZ_DIR"/fuzz_*.py; do
    fuzzer_basename=$(basename "$fuzzer" .py)

    # Compile the fuzzer
    compile_python_fuzzer "$fuzzer"

    # Copy seed corpus if it exists
    corpus_name="${fuzzer_basename#fuzz_}"
    corpus_dir="$FUZZ_DIR/corpus/$corpus_name"
    if [ -d "$corpus_dir" ]; then
        zip -j "$OUT/${fuzzer_basename}_seed_corpus.zip" "$corpus_dir"/* 2>/dev/null || true
    fi
done
