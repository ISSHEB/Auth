package handlers

import (
	"context"
	"encoding/json"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
	"test/auth"
	"test/models"
)

var usersCollection *mongo.Collection
var tokensCollection *mongo.Collection

func LoginHandler(c echo.Context) error {
	var user models.User
	if err := c.Bind(&user); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}
	var storedUser models.User
	err := usersCollection.FindOne(context.Background(), bson.M{"id": user.ID}).Decode(&storedUser)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	accessToken, refreshToken, err := auth.CreateTokenPair(user.ID.Hex())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error creating tokens")
	}
	_, err = tokensCollection.InsertOne(context.Background(), bson.M{"_id": user.ID, "refresh_token": refreshToken})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error saving tokens")
	}
	return c.JSON(http.StatusOK, models.TokenPair{AccessToken: accessToken, RefreshToken: refreshToken})
}

func RefreshHandler(c echo.Context) error {
	var refreshRequest models.RefreshRequest
	if err := c.Bind(&refreshRequest); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}
	var storedToken string
	err := tokensCollection.FindOne(context.Background(), bson.M{"_id": refreshRequest.ID}).Decode(&storedToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	var storedTokenPair models.TokenPair
	err = json.Unmarshal([]byte(storedToken), &storedTokenPair)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error unmarshalling stored token")
	}
	if storedTokenPair.RefreshToken != refreshRequest.RefreshToken {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid refresh token")
	}
	accessToken, refreshToken, err := auth.CreateTokenPair(refreshRequest.ID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error creating new tokens")
	}

	// Update the stored refresh token
	filter := bson.M{"_id": refreshRequest.ID}
	update := bson.M{"$set": bson.M{"refresh_token": refreshToken}}
	result, err := tokensCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error updating stored token")
	}
	if result.MatchedCount == 0 {
		return echo.NewHTTPError(http.StatusInternalServerError, "Error updating stored token")
	}

	return c.JSON(http.StatusOK, models.TokenPair{AccessToken: accessToken, RefreshToken: refreshToken})
}
