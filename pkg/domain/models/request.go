package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RequestResponse struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Request   ParsedRequest      `bson:"request"`
	Response  ParsedResponse     `bson:"response"`
	CreatedAt time.Time          `bson:"created_at"`
}
