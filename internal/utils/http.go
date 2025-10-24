/**
 * Copyright 2025 Dhiego Cassiano Fogaça Barbosa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package utils

import (
	"fmt"
	"net/http"
	"strings"
)

func MountHttpData(r *http.Request, path string) string {
	data := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, path)
	for k, v := range r.Header {
		if k == "Proxy-Authorization" || k == "Proxy-Connection" {
			continue
		}

		if k == "Connection" {
			v = []string{"close"}
		}

		data += fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", "))
	}

	data += "\r\n"
	return data
}
