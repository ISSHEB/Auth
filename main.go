package main

import (
	"context"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"test/handlers"
)

var usersCollection *mongo.Collection
var tokensCollection *mongo.Collection

func main() {
	e := echo.New()

	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		e.Logger.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	usersCollection = client.Database("auth").Collection("users")
	tokensCollection = client.Database("auth").Collection("tokens")

	e.POST("/login", handlers.LoginHandler)
	e.POST("/refresh", handlers.RefreshHandler)

	e.Start(":8080")
}
