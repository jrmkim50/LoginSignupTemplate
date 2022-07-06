package dbhelper

import (
	"github.com/shoppingapp/apiv1/utils"
	"github.com/shoppingapp/apiv1/models"
	"gorm.io/gorm"
	"time"
	"errors"
	"fmt"
	"strings"
)

func LoginUserWithPassword(email, password string) (utils.JWT_TOKEN, utils.JWT_TOKEN, error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	var accessToken, refreshToken utils.JWT_TOKEN
	var loginAttempts models.LoginAttempts
	var user models.User
	loginAttempts, err := GetLoginAttempts(tx, email)
	if err != nil {
		return accessToken, refreshToken, err, utils.GENERIC_LOGIN_ERROR
	}
	if time.Now().After(loginAttempts.BanExpiresAt) {
		loginAttempts.NumAttempts = 0
	}
	result := tx.Raw("SELECT * FROM users WHERE email = ?", email).Scan(&user)
	if result.Error != nil {
		return accessToken, refreshToken, result.Error, utils.GENERIC_LOGIN_ERROR
	}
	compareErr := utils.ComparePasswords(user.PasswordHash, password)
	loginValid := loginAttempts.NumAttempts < utils.MAX_NUM_LOGIN_ATTEMPTS && result.RowsAffected > 0 && compareErr == nil
	accessToken, err = utils.CreateToken(user.DisplayName, "access")
	if err != nil {
		return accessToken, refreshToken, err, utils.GENERIC_LOGIN_ERROR
	}
	refreshToken, err = utils.CreateToken(user.DisplayName, "refresh")
	if err != nil {
		return accessToken, refreshToken, err, utils.GENERIC_LOGIN_ERROR
	}
	tokenObject := models.RefreshToken{
		TokenString: refreshToken.TokenString,
		TokenExpiresAt: refreshToken.ExpireTime,
		User: user,
	}
	if loginValid {
		tokenResult := tx.Create(&tokenObject)
		if tokenResult.Error != nil {
			return refreshToken, accessToken, tokenResult.Error, utils.GENERIC_LOGIN_ERROR
		}
		loginAttempts.NumAttempts = 0
	} else {
		if loginAttempts.NumAttempts < utils.MAX_NUM_LOGIN_ATTEMPTS {
			loginAttempts.NumAttempts++
			loginAttempts.BanExpiresAt = time.Now().Add(time.Minute * utils.LOGIN_BAN_DURATION)
		}
	}
	updateResult := tx.Save(&loginAttempts)
	if updateResult.Error != nil {
		return refreshToken, accessToken, updateResult.Error, utils.GENERIC_LOGIN_ERROR
	}
	tx.Commit()
	if loginValid {
		return accessToken, refreshToken, nil, ""
	} else {
		if loginAttempts.NumAttempts == utils.MAX_NUM_LOGIN_ATTEMPTS {
			errorMessage := "We had some trouble logging you in. " + utils.GenerateBanMessage(loginAttempts.BanExpiresAt)
			return refreshToken, accessToken, errors.New(errorMessage), errorMessage
		}
		return refreshToken, accessToken, errors.New("Login unsuccessful."), utils.GENERIC_LOGIN_ERROR
	}
}

func CreateUser(email, displayName, passwordHash string, refreshToken utils.JWT_TOKEN) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	user := models.User{
		Email: email, 
		PasswordHash: passwordHash, 
		DisplayName: displayName,
		PhoneVerified: false,
	}
	result := tx.Create(&user)
	if result.Error != nil {
		errString := fmt.Sprintf("%v", result.Error)
		if strings.HasPrefix(errString, utils.GORM_ERR_CODE_DUPLICATE_KEY) {
			if strings.HasSuffix(errString, "'users.email'") {
				return result.Error, utils.EMAIL_TAKEN_SIGNUP_ERROR
			} else if strings.HasSuffix(errString, "'users.display_name'") {
				return result.Error, utils.DISPLAY_NAME_TAKEN_SIGNUP_ERROR
			}
		}
		return result.Error, utils.GENERIC_SIGNUP_ERROR
	}
	tokenObject := models.RefreshToken{
		TokenString: refreshToken.TokenString,
		TokenExpiresAt: refreshToken.ExpireTime,
		User: user,
	}
	result = tx.Create(&tokenObject)
	if result.Error != nil {
		return result.Error, utils.GENERIC_SIGNUP_ERROR
	}
	tx.Commit()
	return nil, ""
}

func CreatePasswordResetCode(email string) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	var resetAttempts models.PasswordResetAttempts
	var user models.User
	resetAttempts, err := GetPasswordResetAttempts(tx, email)
	if err != nil {
		return err, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
	}
	if time.Now().After(resetAttempts.RequestsBanExpiresAt) {
		resetAttempts.NumRequests = 0
	}
	userResult := tx.Raw("SELECT * FROM users WHERE email = ?", email).Scan(&user)
	if userResult.Error != nil {
		return userResult.Error, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
	}
	userExists := userResult.RowsAffected > 0
	code := utils.GetVerificationCode()
	if resetAttempts.NumRequests < utils.MAX_NUM_PASS_RESET_CODES {
		resetAttempts.NumRequests++
		resetAttempts.RequestsBanExpiresAt = time.Now().Add(time.Minute * utils.RESET_PASSWORD_REQUEST_BAN_DURATION)
		resetCode := models.PasswordResetCode{
			User: user,
			Code: code, 
			CodeExpiresAt: time.Now().Add(time.Minute * utils.CODE_DURATION),
		}
		if userExists {
			codeResult := tx.Create(&resetCode)
			if codeResult.Error != nil {
				return codeResult.Error, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
			}
			// send email
		}
	}
	updateResult := tx.Save(&resetAttempts)
	if updateResult.Error != nil {
		return updateResult.Error, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
	}
	tx.Commit()
	if resetAttempts.NumRequests < utils.MAX_NUM_PASS_RESET_CODES {
		return nil, ""
	} else {
		errorMessage := "You've been trying to reset your password a lot. " + utils.GenerateBanMessage(resetAttempts.RequestsBanExpiresAt)
		return errors.New(errorMessage), errorMessage
	}
}

func VerifyPasswordResetCode(email, code, passwordHash string) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	var resetAttempts models.PasswordResetAttempts
	var user models.User
	var resetCode models.PasswordResetCode
	resetAttempts, err := GetPasswordResetAttempts(tx, email)
	if err != nil {
		return err, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
	}
	if time.Now().After(resetAttempts.AttemptsBanExpiresAt) {
		resetAttempts.NumAttempts = 0
	}
	userResult := tx.Raw("SELECT * FROM users WHERE email = ?", email).Scan(&user)
	if userResult.Error != nil {
		return userResult.Error, utils.GENERIC_PASSWORD_RESET_ERROR
	}
	codeResult := tx.Raw("SELECT * FROM password_reset_codes WHERE user_id = ? AND code = ?", user.ID, code).Scan(&resetCode)
	if codeResult.Error != nil {
		return codeResult.Error, utils.GENERIC_PASSWORD_RESET_ERROR
	}
	codeValid := codeResult.RowsAffected > 0 && time.Now().Before(resetCode.CodeExpiresAt)
	if resetAttempts.NumAttempts < utils.MAX_NUM_PASS_RESET_ATTEMPTS {
		if codeValid  {
			resetAttempts.NumAttempts = 0
			user.PasswordHash = passwordHash
			updateResult := tx.Save(&user)
			if updateResult.Error != nil {
				return updateResult.Error, utils.GENERIC_PASSWORD_RESET_ERROR
			}
			codeDelete := tx.Exec("DELETE FROM password_reset_codes WHERE id = ?", resetCode.ID)
			if codeDelete.Error != nil {
				return codeDelete.Error, utils.GENERIC_PASSWORD_RESET_ERROR
			}
			deleteResult := tx.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", user.ID)
			if deleteResult.Error != nil {
				return deleteResult.Error, utils.GENERIC_PASSWORD_RESET_ERROR
			}
			// send email notifying of password change
		} else {
			resetAttempts.NumAttempts++
			resetAttempts.AttemptsBanExpiresAt = time.Now().Add(time.Minute * utils.RESET_PASSWORD_BAN_DURATION)
		}
	}
	updateResult := tx.Save(&resetAttempts)
	if updateResult.Error != nil {
		return updateResult.Error, utils.GENERIC_PASSWORD_RESET_ERROR
	}
	tx.Commit()
	if resetAttempts.NumAttempts < utils.MAX_NUM_PASS_RESET_ATTEMPTS {
		return nil, ""
	} else {
		errorMessage := "We had some trouble resetting your password. " + utils.GenerateBanMessage(resetAttempts.AttemptsBanExpiresAt)
		return errors.New(errorMessage), errorMessage
	}
}

func RefreshTokenExists(displayName, tokenString string) bool {
	tx := DB.Begin()
	defer tx.Rollback()
	var user models.User
	var refreshToken models.RefreshToken
	tx.Raw("SELECT * FROM users WHERE display_name = ?", displayName).Scan(&user)
	tokenResult := tx.Raw(
		"SELECT * FROM refresh_tokens WHERE token_string = ? AND user_id = ?", 
		tokenString, 
		user.ID,
	).Scan(&refreshToken)
	tx.Commit()
	if tokenResult.Error != nil || tokenResult.RowsAffected == 0 {
		return false;
	}
	if time.Now().After(refreshToken.TokenExpiresAt) {
		return false;
	}
	return true;
}

func GetLoginAttempts(tx *gorm.DB, email string) (models.LoginAttempts, error) {
	var loginAttempts models.LoginAttempts
	result := tx.Raw("SELECT * FROM login_attempts WHERE email = ? FOR UPDATE", email).Scan(&loginAttempts)
	if result.Error != nil {
		return loginAttempts, result.Error
	}
	if result.RowsAffected == 0 {
		loginAttempts = models.LoginAttempts{
			Email: email,
			NumAttempts: 0,
			BanExpiresAt: time.Now(),
		}
		createResult := tx.Create(&loginAttempts)
		if createResult.Error != nil {
			return loginAttempts, createResult.Error
		}
	}
	return loginAttempts, nil
}

func GetPasswordResetAttempts(tx *gorm.DB, email string) (models.PasswordResetAttempts, error) {
	var resetAttempts models.PasswordResetAttempts
	result := tx.Raw("SELECT * FROM password_reset_attempts WHERE email = ? FOR UPDATE", email).Scan(&resetAttempts)
	if result.Error != nil {
		return resetAttempts, result.Error
	}
	if result.RowsAffected == 0 {
		resetAttempts = models.PasswordResetAttempts{
			Email: email,
			NumRequests: 0,
			RequestsBanExpiresAt: time.Now(),
			NumAttempts: 0,
			AttemptsBanExpiresAt: time.Now(),
		}
		createResult := tx.Create(&resetAttempts)
		if createResult.Error != nil {
			return resetAttempts, createResult.Error
		}
	}
	return resetAttempts, nil
}