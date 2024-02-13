package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID    primitive.ObjectID `json:"_id" bson:"_id"`
	IDStr string             `json:"id" bson:"id"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshRequest struct {
	ID           string `json:"id" bson:"_id"`
	RefreshToken string `json:"refresh_token"`
}
