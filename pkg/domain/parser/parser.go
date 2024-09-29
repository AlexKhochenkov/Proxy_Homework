package parser

import (
	"net/http"
	"strings"

	"Proxy/pkg/domain/models"
)

func ParseRequest(r *http.Request) models.ParsedRequest {
	parsedReq := models.ParsedRequest{
		Method:    r.Method,
		Path:      r.URL.Path,
		GetParams: parseQueryParams(r.URL.Query()),
		Headers:   parseHeaders(r.Header),
		Cookies:   parseCookies(r.Cookies()),
	}

	if r.Method == http.MethodPost && strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		err := r.ParseForm()
		if err == nil {
			parsedReq.PostParams = parseFormParams(r.PostForm)
		}
	}

	return parsedReq
}

func ParseResponse(resp *http.Response, body string) models.ParsedResponse {
	return models.ParsedResponse{
		Code:    resp.StatusCode,
		Message: resp.Status,
		Headers: parseHeaders(resp.Header),
		Body:    body,
	}
}

func parseQueryParams(params map[string][]string) map[string]string {
	result := make(map[string]string)
	for key, values := range params {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

func parseHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		result[key] = strings.Join(values, ", ")
	}
	return result
}

func parseCookies(cookies []*http.Cookie) map[string]string {
	result := make(map[string]string)
	for _, cookie := range cookies {
		result[cookie.Name] = cookie.Value
	}
	return result
}

func parseFormParams(form map[string][]string) map[string]string {
	result := make(map[string]string)
	for key, values := range form {
		result[key] = strings.Join(values, ", ")
	}
	return result
}
