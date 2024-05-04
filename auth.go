package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"gitlab.com/developerdurp/logger"
)

type StandardMessage struct {
	Message string `json:"message" example:"message"`
}

func failedReponse(message string, w http.ResponseWriter) {
	response := StandardMessage{
		Message: message,
	}

	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		logger.LogError("Failed to Encode")
	}
}

func AuthMiddleware(next http.Handler, allowedGroups []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var groups []string
		JwksURL := os.Getenv("jwksurl")
		tokenString := w.Header().Get("Authorization")

		if tokenString == "" {
			failedReponse("No Token Detected", w)
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		ctx, cancel := context.WithCancel(context.Background())

		options := keyfunc.Options{
			Ctx: ctx,
			RefreshErrorHandler: func(err error) {
				logger.LogError("There was an error with the jwt.Keyfunc" + err.Error())
			},
			RefreshInterval:   time.Hour,
			RefreshRateLimit:  time.Minute * 5,
			RefreshTimeout:    time.Second * 10,
			RefreshUnknownKID: true,
		}

		jwks, err := keyfunc.Get(JwksURL, options)
		if err != nil {
			failedReponse("Failed to create JWKS:"+err.Error(), w)

			cancel()
			jwks.EndBackground()
			return
		}

		token, err := jwt.Parse(tokenString, jwks.Keyfunc)
		if err != nil {
			failedReponse(err.Error(), w)

			cancel()
			jwks.EndBackground()
			return
		}

		if !token.Valid {
			failedReponse("Token is invalid: "+err.Error(), w)

			cancel()
			jwks.EndBackground()
			return
		}

		cancel()
		jwks.EndBackground()

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			failedReponse("Invalid authorization token claims", w)
			return
		}

		groupsClaim, ok := claims["groups"].([]interface{})
		if !ok {
			failedReponse("Missing or invalid groups claim in the authorization token", w)
			return
		}

		for _, group := range groupsClaim {
			if groupName, ok := group.(string); ok {
				groups = append(groups, groupName)
			}
		}

		isAllowed := false
		for _, allowedGroup := range allowedGroups {
			for _, group := range groups {
				if group == allowedGroup {
					isAllowed = true
					break
				}
			}
			if isAllowed {
				break
			}
		}

		if !isAllowed {
			failedReponse("Unaothorized to use this endpoint", w)
			return
		}

		next.ServeHTTP(w, r)
	})
}
