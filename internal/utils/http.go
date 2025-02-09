package utils

import (
	"crypto/tls"
	"time"

	"github.com/go-resty/resty/v2"
)

type HTTPClientManager struct {
	client *resty.Client
}

func NewHTTPClient(timeout time.Duration) *HTTPClientManager {
	client := resty.New().
		SetTimeout(timeout).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	return &HTTPClientManager{client: client}
}

func (h *HTTPClientManager) Get(url string) (string, error) {
	resp, err := h.client.R().Get(url)
	if err != nil {
		return "", err
	}
	return resp.String(), nil
}

func (h *HTTPClientManager) GetJSON(url string, result interface{}) error {
	resp, err := h.client.R().SetResult(result).Get(url)
	if err != nil {
		return err
	}
	if resp.IsError() {
		return err
	}
	return nil
}
