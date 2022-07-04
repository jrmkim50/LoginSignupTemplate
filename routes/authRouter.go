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

type RequestBody interface {
	SignupAttempt | LoginAttempt | PasswordResetRequest
}

func AuthRouter(s *mux.Router) {
	s.HandleFunc("/login", Login).Methods("POST")
	s.HandleFunc("/signup", Signup).Methods("POST")
	s.HandleFunc("/request_password_reset", RequestPasswordReset).Methods("POST")
	s.HandleFunc("/reset_password", ResetPassword).Methods("POST")
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
		AccessToken: accessToken.TokenString, 
		RefreshToken: refreshToken.TokenString,
	})
}

func Signup(w http.ResponseWriter, r *http.Request) {
	signupAttempt, err := DecodeValidBody[SignupAttempt](r)
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_LOGIN_ERROR)
		return
	}
	accessToken, err := utils.CreateToken(signupAttempt.DisplayName, "access")
	if err != nil {
		GenericAuthError(w, err, utils.GENERIC_SIGNUP_ERROR)
		return
	}
	refreshToken, err := utils.CreateToken(signupAttempt.DisplayName, "refresh")
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
		AccessToken: accessToken.TokenString, 
		RefreshToken: refreshToken.TokenString,
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
		Status: "New verification code sent!",
	})
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {

}