package middlewares

import (
	"github.com/shoppingapp/apiv1/utils"
	"net/http"
	"strings"
	"errors"
	"log"
)

func GetTokenFromAuthorizationHeader(authHeader string) (string, error) {
	if len(authHeader) == 0 {
		return "", errors.New(utils.MISSING_REQUEST_DATA)
	}
	bearer_token := strings.Split(authHeader, " ")
	if len(bearer_token) < 2 {
		return "", errors.New(utils.MISSING_REQUEST_DATA)
	}
	return bearer_token[1], nil
}

func IsAccessTokenAuthorized(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("authorization")
		accessTokenString, err := GetTokenFromAuthorizationHeader(authorization)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_, err, errMessage := utils.VerifyJWTToken(utils.ACCESS_TYPE, accessTokenString)
		if err != nil {
			// in FE, use the refresh token to get a new access token now
			log.Println(err)
			http.Error(w, errMessage, http.StatusBadRequest)
			return
		}
		f(w, r)
	}
}