package http

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/gorilla/mux"

	"Proxy/pkg/domain/models"
	"Proxy/pkg/repository/mongodb"
)

type Handler struct {
	Repo *mongodb.RequestRepository
}

func NewHandler(repo *mongodb.RequestRepository) *Handler {
	return &Handler{
		Repo: repo,
	}
}

// HandleGetAllRequests
// @Summary Get all requests
// @Description Возвращает список всех запросов, сохраненных в базе данных
// @Tags requests
// @Produce json
// @Success 200 {array} models.RequestResponse
// @Failure 500 {string} string "Failed to fetch requests"
// @Router /api/v1/requests [get]
func (h *Handler) HandleGetAllRequests(w http.ResponseWriter, r *http.Request) {
	requests, err := h.Repo.GetAllRequests(context.TODO())
	if err != nil {
		http.Error(w, "Ошибка при получении запросов", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(requests)
}

// HandleGetRequestByID
// @Summary Get request by ID
// @Description Возвращает конкретный запрос по его ID
// @Tags requests
// @Param id path string true "Request ID"
// @Produce json
// @Success 200 {object} models.RequestResponse
// @Failure 400 {string} string "Invalid request ID"
// @Failure 404 {string} string "Request not found"
// @Router /api/v1/requests/{id} [get]
func (h *Handler) HandleGetRequestByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		http.Error(w, "Ошибка при выполнении запроса", http.StatusBadRequest)
		return
	}

	request, err := h.Repo.GetRequestByID(context.TODO(), id)
	if err != nil {
		http.Error(w, "Запрос не найден", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(request)
}

// HandleRepeatRequest
// @Summary Repeat a request by ID
// @Description Повторно отправляет запрос, сохраненный по его ID, и возвращает результат
// @Tags requests
// @Param id path string true "Request ID"
// @Produce json
// @Success 200 {object} models.ParsedResponse
// @Failure 400 {string} string "Invalid request ID"
// @Failure 404 {string} string "Request not found"
// @Failure 500 {string} string "Failed to repeat request"
// @Router /api/v1/repeat/{id} [post]
func (h *Handler) HandleRepeatRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		http.Error(w, "Неправильный ID", http.StatusBadRequest)
		return
	}

	req, err := h.Repo.GetRequestByID(context.TODO(), id)
	if err != nil {
		http.Error(w, "Запрос не найден", http.StatusNotFound)
		return
	}

	res, err := sendRequest(req)
	if err != nil {
		http.Error(w, "Ошибка при выполнении запроса", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(res)
}

func sendRequest(request *models.RequestResponse) (string, error) {
	var requestCurl bytes.Buffer

	requestCurl.WriteString("curl -x http://127.0.0.1:8080 ")
	if request.Request.Method != "CONNECT" {
		requestCurl.WriteString("-X ")
		requestCurl.WriteString(request.Request.Method)
	}

	for key, value := range request.Request.GetParams {
		requestCurl.WriteString(fmt.Sprintf(" -G --data-urlencode \"%s=%s\"", key, value))
	}

	for key, value := range request.Request.PostParams {
		requestCurl.WriteString(fmt.Sprintf(" -d \"%s=%s\"", key, value))
	}

	for key, value := range request.Request.Headers {
		requestCurl.WriteString(fmt.Sprintf(" -H \"%s: %s\"", key, value))
	}

	for key, value := range request.Request.Cookies {
		requestCurl.WriteString(fmt.Sprintf(" --cookie \"%s=%s\"", key, value))
	}

	requestCurl.WriteString(" " + request.Request.Path)

	s := requestCurl.String()
	cmd := exec.Command("bash", "-c", s)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ошибка при выполнении команды curl: %v, вывод: %s", err, out)
	}

	res := strings.Split(string(out), "<html>")
	result := strings.Join(res[len(res)-1:], "<html>")
	return "<html>" + result, nil
}

// HandleScanRequest
// @Summary Scan request by ID for vulnerabilities
// @Description Проверяет запрос по его ID на уязвимости Param-miner
// @Tags requests
// @Param id path string true "Request ID"
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 400 {string} string "Invalid request ID"
// @Failure 404 {string} string "Request not found"
// @Router /api/v1/scan/{id} [get]
func (h *Handler) HandleScanRequest(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(vars["id"])
	if err != nil {
		http.Error(w, "Неправильный ID", http.StatusBadRequest)
		return
	}

	reqResp, err := h.Repo.GetRequestByID(context.TODO(), id)
	if err != nil {
		http.Error(w, "Запрос не найден", http.StatusNotFound)
		return
	}

	vulnerabilities, err := checkParamMiner(reqResp)
	if err != nil {
		http.Error(w, "Ошибка при сканировании", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status":  200,
		"message": "success",
		"payload": vulnerabilities,
	}
	json.NewEncoder(w).Encode(response)
}

func ReadParams(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Не удалось открыть файл: %v", err)
		return []string{""}, err
	}
	defer file.Close()

	var params []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := scanner.Text()
		params = append(params, word)
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Ошибка при чтении файла: %v", err)
		return []string{""}, err
	}

	return params, nil
}

func modifyRequest(request *models.RequestResponse, param string) (*models.RequestResponse, string) {
	newRandom := randomString(8)
	request.Request.GetParams[param] = newRandom

	return request, newRandom
}

func checkParamMiner(request *models.RequestResponse) ([]string, error) {
	var results []string
	var getParams []string
	getParams, err := ReadParams("pkg/api/http/params.txt")
	if err != nil {
		return []string{""}, fmt.Errorf("Ошибка при считывании параметров: %v", err)
	}
	for _, getParam := range getParams {

		modifiedRequest, random := modifyRequest(request, getParam)
		modifiedResponse, err := sendRequest(modifiedRequest)
		if err != nil {
			continue
		}
		if strings.Contains(modifiedResponse, random) {
			results = append(results, fmt.Sprintf("Параметр '%s' был выявлен со значением '%s'\n", getParam, random))
		}
	}

	if len(results) == 0 {
		return []string{"Param-miner не сработал, уязвимостей не найдено"}, nil
	}
	return results, nil
}

func randomString(length int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	rand.Seed(time.Now().UnixNano())

	s := make([]rune, length)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}

	return string(s)
}
