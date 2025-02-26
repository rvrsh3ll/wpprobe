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

package utils

import (
	"crypto/tls"
	"errors"
	"io"
	"time"

	"github.com/corpix/uarand"
	"github.com/go-resty/resty/v2"
)

const maxResponseSizeMB = 20

var maxResponseSize = maxResponseSizeMB * 1024 * 1024

type HTTPClientManager struct {
	client *resty.Client
}

type SilentLogger struct{}

func (s *SilentLogger) Printf(string, ...interface{}) {}
func (s *SilentLogger) Debugf(string, ...interface{}) {}
func (s *SilentLogger) Errorf(string, ...interface{}) {}
func (s *SilentLogger) Warnf(string, ...interface{})  {}

func NewHTTPClient(timeout time.Duration) *HTTPClientManager {
	client := resty.New().
		SetTimeout(timeout).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetRedirectPolicy(resty.NoRedirectPolicy()).
		SetRetryCount(2).
		SetLogger(&SilentLogger{})

	client.OnBeforeRequest(func(c *resty.Client, r *resty.Request) error {
		r.SetHeader("User-Agent", uarand.GetRandom())
		return nil
	})

	return &HTTPClientManager{client: client}
}

func (h *HTTPClientManager) Get(url string) (string, error) {
	resp, err := h.client.R().SetDoNotParseResponse(true).Get(url)
	if err != nil {
		return "", err
	}

	if resp == nil || resp.RawBody() == nil {
		return "", errors.New("empty response")
	}
	defer resp.RawBody().Close()

	limited := io.LimitReader(resp.RawBody(), int64(maxResponseSize))
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}

	if len(data) == 0 {
		return "", errors.New("empty response")
	}

	if len(data) >= maxResponseSize {
		return "", errors.New("response too large")
	}

	return string(data), nil
}
