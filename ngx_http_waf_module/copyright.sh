#!/bin/bash

# Define the copyright header
COPYRIGHT_HEADER="\
/*
 * Copyright (C) 2024 Cloud Rhino Pty Ltd
 * 
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * This module contains parts under a dual-license:
 * Only the 'enable_protocol_attack' and 'enable_general_rules' features are 
 * covered by the Apache 2.0 License, other features require a commercial license.
 * 
 * GitHub Repo: https://github.com/cloudrhinoltd/ngx-waf-protect
 * Contact Email: cloudrhinoltd@gmail.com
 */
"

# Function to prepend the copyright header to a file
prepend_copyright() {
    local file="$1"
    if ! grep -q "Copyright (C) 2024 Cloud Rhino Pty Ltd" "$file"; then
        echo -e "$COPYRIGHT_HEADER\n$(cat "$file")" > "$file"
        echo "Added copyright header to $file"
    else
        echo "Copyright header already exists in $file"
    fi
}

# Find all .cpp and .h files and apply the copyright header
find ./src ./include -type f \( -name "*.cpp" -o -name "*.h" \) | while read -r file; do
    prepend_copyright "$file"
done

echo "Finished applying copyright headers."
