package utils

import (
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt"
	"github.com/xlzd/gotp"
	"encoding/base64"
	"time"
	"os"
	"fmt"
	"errors"
)

var secretLength int = 16
var totp *gotp.TOTP = gotp.NewDefaultTOTP(gotp.RandomSecret(secretLength))

type JWT_TOKEN struct {
	TokenString string
	ExpireTime time.Time
}

func HashPassword(password string) (string, error) {
	const HASH_ROUNDS = 10
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), HASH_ROUNDS)
	return string(bytes), err
}

func ComparePasswords(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func GetJWTSecret(tokenType string, getOldKey bool) ([]byte, error) {
	var b64String string
	if tokenType == REFRESH_TYPE {
		b64String = os.Getenv(JWT_SECRET_KEY_REFRESH)
		if getOldKey {
			b64String = os.Getenv(JWT_SECRET_KEY_REFRESH_OLD)	
		}
	} else {
		b64String = os.Getenv(JWT_SECRET_KEY_ACCESS)
		if getOldKey {
			b64String = os.Getenv(JWT_SECRET_KEY_ACCESS_OLD)	
		}
	}
	return base64.StdEncoding.DecodeString(b64String)
}

func CreateToken(displayName, tokenType string) (JWT_TOKEN, error) {
	var jwtToken JWT_TOKEN
	signingKey, err := GetJWTSecret(tokenType, false)
	if err != nil {
		return jwtToken, err
	}
	claims := jwt.MapClaims{}
	claims["displayName"] = displayName
	claims["tokenType"] = tokenType
	if tokenType == REFRESH_TYPE {
		jwtToken.ExpireTime = time.Now().Add(time.Hour * 24 * REFRESH_TOKEN_DURATION)
	} else {
		jwtToken.ExpireTime = time.Now().Add(time.Minute * ACCESS_TOKEN_DURATION)
	}
	claims["exp"] = jwtToken.ExpireTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return jwtToken, err
	}
	jwtToken.TokenString = tokenString
	return jwtToken, nil
}

func ParseJWTToken(tokenString string, signingKey []byte) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("There was an error in parsing.")
		}
		return signingKey, nil
	})
}

// func VerifyJWTToken(tokenType, tokenString string) (*jwt.Token, error) {
// 	signingKey, err := GetJWTSecret(tokenType, false)
// 	oldSigningKey, err := GetJWTSecret(tokenType, true)
	
// 	token, err := ParseJWTToken(tokenString, signingKey)
// 	if err != nil {
// 		token, err = ParseJWTToken(tokenString, oldSigningKey)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}

// 	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
// 		if tokenType == REFRESH_TYPE {
// 			displayName, ok := claims["displayName"].(string)
// 			if !ok {
// 				return "", errors.New("Trouble parsing token.")
// 			}
// 			tokenExists := RefreshTokenExists(displayName, tokenString)
// 			if !tokenExists {
// 				return "", errors.New("Trouble parsing token.")
// 			}
// 		}
// 		return token, nil
// 	}
// 	return nil, errors.New("Token expired.")
// }

// func RefreshJWTToken(refreshTokenString string) (string, string, error) {	
// 	refreshToken, verifyErr := VerifyJWTToken(REFRESH_TYPE, refreshTokenString)
// 	if verifyErr != nil {
// 		return "", "", verifyErr
// 	}
// 	claims, _ := refreshToken.Claims.(jwt.MapClaims); 
// 	displayName, ok := claims["displayName"].(string)
// 	if !ok {
// 		return "", "", errors.New("Trouble parsing token.")
// 	}
// 	accessToken, err := CreateToken(displayName, ACCESS_TYPE)
// 	if err != nil {
// 		return "", "", err
// 	}
// 	newrRefreshToken, err := CreateToken(displayName, REFRESH_TYPE)
// 	if err != nil {
// 		return "", "", err
// 	}
// 	return accessToken.TokenString, newrRefreshToken.TokenString, nil
// }

func GetVerificationCode() string {
	return totp.Now()
}

func GenerateBanMessage(banExpAt time.Time) string {
	diff := banExpAt.Sub(time.Now())
	timeLeft := int(diff.Round(time.Minute).Minutes())
	errorMessage := fmt.Sprintf("Try again in %d minutes.", timeLeft)
	if timeLeft <= 1 {
		errorMessage = fmt.Sprintf("Try again in 1 minute.")
	}
	return errorMessage
}