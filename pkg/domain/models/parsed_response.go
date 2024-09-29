package models

type ParsedResponse struct {
	Code    int               `json:"code"`
	Message string            `json:"message"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}
