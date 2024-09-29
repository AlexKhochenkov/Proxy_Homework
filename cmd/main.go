package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	_ "github.com/jackc/pgx/stdlib"

	"Proxy/pkg/api/middleware"

	hand "Proxy/pkg/api/http"
	repo "Proxy/pkg/repository/mongodb"

	httpSwagger "github.com/swaggo/http-swagger"

	_ "Proxy/docs"
)

// @title API Proxy
// @version 1.0
// @description API server for proxy

// @host localhost:8000
// @BasePath /
func main() {
	client, collection := initializeDatabase()
	defer func() {
		if err := client.Disconnect(context.Background()); err != nil {
			log.Fatalf("Error disconnecting MongoDB: %v", err)
		}
	}()

	router := setupRouter(client, collection)
	startServer(router)
}

func initializeDatabase() (*mongo.Client, *mongo.Collection) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI("mongodb://mongo-container:27017")

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("MongoDB is not available: %v", err)
	}

	fmt.Println("Connected to MongoDB!")

	collection := client.Database("web").Collection("requests")

	return client, collection
}

func initializeHandler(collection *mongo.Collection) *hand.Handler {
	requestRepo := repo.NewRequestRepository(collection)

	return hand.NewHandler(requestRepo)
}

func setupRouter(client *mongo.Client, collection *mongo.Collection) http.Handler {
	router := mux.NewRouter()

	apiRouter := setupLogRouter(collection)
	router.PathPrefix("/api/v1").Handler(apiRouter)

	router.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	return middleware.RequestLogger(router)
}

func setupLogRouter(collection *mongo.Collection) http.Handler {
	apiRouter := mux.NewRouter().PathPrefix("/api/v1").Subrouter()

	handlerRequest := initializeHandler(collection)

	apiRouter.HandleFunc("/requests", handlerRequest.HandleGetAllRequests).Methods("GET", "OPTIONS")
	apiRouter.HandleFunc("/requests/{id}", handlerRequest.HandleGetRequestByID).Methods("GET", "OPTIONS")
	apiRouter.HandleFunc("/repeat/{id}", handlerRequest.HandleRepeatRequest).Methods("POST", "OPTIONS")
	apiRouter.HandleFunc("/scan/{id}", handlerRequest.HandleScanRequest).Methods("GET", "OPTIONS")

	return apiRouter
}

func startServer(router http.Handler) {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8000", "http://localhost:8080"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodPut, http.MethodOptions},
		AllowCredentials: true,
		AllowedHeaders:   []string{"X-Csrf-Token", "Content-Type", "AuthToken"},
		ExposedHeaders:   []string{"X-Csrf-Token", "AuthToken"},
	})

	corsHandler := c.Handler(router)

	fmt.Printf("The server is running on http://localhost:%d\n", 8000)
	fmt.Printf("Swagger is running on http://localhost:%d/swagger/index.html\n", 8000)

	err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", 8000), corsHandler)
	if err != nil {
		log.Fatalf("Error when starting the server: %v", err)
		return
	}
}
