package routes

import (
	"github.com/shoppingapp/apiv1/dbhelper"
	"github.com/shoppingapp/apiv1/utils"
	"github.com/gorilla/mux"
	"net/http"
	"encoding/json"
	"log"
)

type TokenResponse struct {
	AccessToken string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type StatusResponse struct {
	Status string `json:"status"`
}

type SignupAttempt struct {
	Email string `validate:"required,email"`
	DisplayName string `validate:"required,min=4,max=64"`
	Password string `validate:"required,min=8,max=64,eqfield=ConfirmPassword"`
	ConfirmPassword string `validate:"required,min=8,max=64"`
}

type LoginAttempt struct {
	Email string `validate:"required,email"`
	Password string `validate:"required"`
}

type PasswordResetRequest struct {
	Email string `validate:"required,email"`
}

type PasswordResetAttempt struct {
	Email string `validate:"required,email"`
	Code string `validate:"required"`
	Password string `validate:"required,min=8,max=64,eqfield=ConfirmPassword"`
	ConfirmPassword string `validate:"required,min=8,max=64"`
}

type RefreshTokenBody struct {
	TokenString string `validate:"required"`
}

type RequestBody interface {
	SignupAttempt | LoginAttempt | PasswordResetRequest | PasswordResetAttempt | RefreshTokenBody
}

func AuthRouter(s *mux.Router) {
	s.HandleFunc("/login", Login).Methods("POST")
	s.HandleFunc("/signup", Signup).Methods("POST")
	s.HandleFunc("/request_password_reset", RequestPasswordReset).Methods("POST")
	s.HandleFunc("/reset_password", ResetPassword).Methods("POST")
	s.HandleFunc("/refresh_jwt_token", RefreshJWTToken).Methods("POST")
}

func GenericAuthError(w http.ResponseWriter, err error, errorMessage string) {
	log.Println(err)
	http.Error(w, errorMessage, http.StatusBadRequest)
}

func DecodeValidBody[B RequestBody](r *http.Request) (B, error) {
	decoder := json.NewDecoder(r.Body)
	var requestBody B
	err := decoder.Decode(&requestBody)
	if err != nil {
		return requestBody, err
	}
	err = validate.Struct(requestBody)
	if err != nil {
		return requestBody, err
	}
	return requestBody, nil
}

func Login(w http.ResponseWriter, r *http.Request) {
	loginAttempt, err := DecodeValidBody[LoginAttempt](r)
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_LOGIN_ERROR)
		return
	}
	accessToken, refreshToken, err, errMessage := dbhelper.LoginUserWithPassword(
		loginAttempt.Email, 
		loginAttempt.Password, 
	)
	if err != nil {
		GenericAuthError(w, err, errMessage)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: accessToken, 
		RefreshToken: refreshToken,
	})
}

func Signup(w http.ResponseWriter, r *http.Request) {
	signupAttempt, err := DecodeValidBody[SignupAttempt](r)
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_LOGIN_ERROR)
		return
	}
	accessToken, err := utils.CreateJWTToken(signupAttempt.DisplayName, "access")
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_SIGNUP_ERROR)
		return
	}
	refreshToken, err := utils.CreateJWTToken(signupAttempt.DisplayName, "refresh")
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_SIGNUP_ERROR)
		return
	}
	passwordHash, err := utils.HashPassword(signupAttempt.Password)
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_SIGNUP_ERROR)
		return
	}
	err, errMessage := dbhelper.CreateUser(
		signupAttempt.Email, 
		signupAttempt.DisplayName, 
		passwordHash, 
		refreshToken,
	)
	if err != nil {
		GenericAuthError(w, err, errMessage)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: accessToken, 
		RefreshToken: refreshToken,
	})
}

func RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	passwordResetRequest, err := DecodeValidBody[PasswordResetRequest](r)
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR)
		return
	}
	err, errMessage := dbhelper.CreatePasswordResetCode(passwordResetRequest.Email)
	if err != nil {
		GenericAuthError(w, err, errMessage)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StatusResponse{
		Status: "Check your email! A verification code has been sent if an account was found with this email.",
	})
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	passwordResetAttempt, err := DecodeValidBody[PasswordResetAttempt](r)
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_PASSWORD_RESET_ERROR)
		return
	}
	passwordHash, err := utils.HashPassword(passwordResetAttempt.Password)
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_PASSWORD_RESET_ERROR)
		return
	}
	err, errMessage := dbhelper.VerifyPasswordResetCode(
		passwordResetAttempt.Email, 
		passwordResetAttempt.Code, 
		passwordHash,
	)
	if err != nil {
		GenericAuthError(w, err, errMessage)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StatusResponse{
		Status: "The password has been reset if an account was found with this email! Please log in now.",
	})
}

func RefreshJWTToken(w http.ResponseWriter, r *http.Request) {
	refreshTokenBody, err := DecodeValidBody[RefreshTokenBody](r)
	if err != nil {
		GenericAuthError(w, err, utils.JWT_TOKEN_PARSING_ERROR)
		return
	}
	claims, err, errMessage := utils.VerifyJWTToken(utils.REFRESH_TYPE, refreshTokenBody.TokenString)
	if err != nil {
		// if err, then the refresh token is not valid anymore, and you need to log in again
		GenericAuthError(w, err, errMessage)
		return
	}
	displayName, ok := claims["displayName"].(string)
	if !ok {
		GenericAuthError(w, err, utils.JWT_TOKEN_PARSING_ERROR)
		return
	}
	newAccessToken, err := utils.CreateJWTToken(displayName, "access")
	if err != nil {
		GenericAuthError(w, err, utils.JWT_TOKEN_PARSING_ERROR)
		return
	}
	newRefreshToken, err := utils.CreateJWTToken(displayName, "refresh")
	if err != nil {
		GenericAuthError(w, err, utils.JWT_TOKEN_PARSING_ERROR)
		return
	}
	err, errMessage = dbhelper.ReplaceRefreshToken(displayName, refreshTokenBody.TokenString, newRefreshToken)
	if err != nil {
		GenericAuthError(w, err, errMessage)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: newAccessToken, 
		RefreshToken: newRefreshToken,
	})
}