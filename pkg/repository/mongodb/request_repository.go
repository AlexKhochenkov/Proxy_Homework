package mongodb

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"Proxy/pkg/domain/models"
)

type RequestRepository struct {
	Collection *mongo.Collection
}

func NewRequestRepository(collection *mongo.Collection) *RequestRepository {
	return &RequestRepository{
		Collection: collection,
	}
}

func (r *RequestRepository) AddRequestResponse(ctx context.Context, req models.ParsedRequest, resp models.ParsedResponse) (primitive.ObjectID, error) {
	record := models.RequestResponse{
		Request:   req,
		Response:  resp,
		CreatedAt: time.Now(),
	}

	result, err := r.Collection.InsertOne(ctx, record)
	if err != nil {
		return primitive.NilObjectID, err
	}

	return result.InsertedID.(primitive.ObjectID), nil
}

func (r *RequestRepository) GetAllRequests(ctx context.Context) ([]models.RequestResponse, error) {
	cursor, err := r.Collection.Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var requests []models.RequestResponse
	if err := cursor.All(ctx, &requests); err != nil {
		return nil, err
	}

	return requests, nil
}

func (r *RequestRepository) GetRequestByID(ctx context.Context, id primitive.ObjectID) (*models.RequestResponse, error) {
	var request models.RequestResponse
	err := r.Collection.FindOne(ctx, bson.M{"_id": id}).Decode(&request)
	if err != nil {
		return nil, err
	}

	return &request, nil
}
