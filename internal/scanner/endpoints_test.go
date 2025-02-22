// Copyright (c) 2025 Valentin Lobstein (Chocapikk) <balgogan@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
)

func TestFetchEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		mockServer func(w http.ResponseWriter, r *http.Request)
		want       []string
	}{
		{
			name: "Valid response with routes",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"routes": map[string]interface{}{
						"/wp/v2/posts":      nil,
						"/wp/v2/comments":   nil,
						"/wp/v2/categories": nil,
					},
				}
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Errorf("Failed to encode JSON response: %v", err)
				}
			},
			want: []string{"/wp/v2/posts", "/wp/v2/comments", "/wp/v2/categories"},
		},
		{
			name: "Response without routes",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				response := map[string]interface{}{
					"data": "No routes here",
				}
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Errorf("Failed to encode JSON response: %v", err)
				}
			},
			want: []string{},
		},
		{
			name: "Invalid JSON response",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				if _, err := w.Write([]byte("{invalid-json")); err != nil {
					t.Errorf("Failed to write invalid JSON: %v", err)
				}
			},
			want: []string{},
		},
		{
			name: "HTTP error response",
			mockServer: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.mockServer))
			defer server.Close()

			got := FetchEndpoints(server.URL)

			sort.Strings(got)
			sort.Strings(tt.want)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FetchEndpoints() = %v, want %v", got, tt.want)
			}
		})
	}
}
