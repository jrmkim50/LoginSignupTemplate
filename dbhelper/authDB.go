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

func LoginUserWithPassword(email, password string) (string, string, error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	var accessToken, refreshToken string
	var loginAttempts models.LoginAttempts
	var user models.User
	loginAttempts, err := _GetLoginAttempts(tx, email)
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
	accessToken, err = utils.CreateJWTToken(user.DisplayName, "access")
	if err != nil {
		return accessToken, refreshToken, err, utils.GENERIC_LOGIN_ERROR
	}
	refreshToken, err = utils.CreateJWTToken(user.DisplayName, "refresh")
	if err != nil {
		return accessToken, refreshToken, err, utils.GENERIC_LOGIN_ERROR
	}
	tokenObject := models.RefreshToken{
		TokenString: refreshToken,
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
			errorMessage := utils.GenerateBanMessage(loginAttempts.BanExpiresAt)
			return refreshToken, accessToken, errors.New(errorMessage), errorMessage
		}
		return refreshToken, accessToken, errors.New("Login unsuccessful."), utils.GENERIC_LOGIN_ERROR
	}
}

func CreateUser(email, displayName, passwordHash, refreshToken string) (error, string) {
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
		TokenString: refreshToken,
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
	resetAttempts, err := _GetPasswordResetAttempts(tx, email)
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
		errorMessage := utils.GenerateBanMessage(resetAttempts.RequestsBanExpiresAt)
		return errors.New(errorMessage), errorMessage
	}
}

func VerifyPasswordResetCode(email, code, passwordHash string) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	var resetAttempts models.PasswordResetAttempts
	var user models.User
	var resetCode models.PasswordResetCode
	// Block logins from happening
	_, err := _GetLoginAttempts(tx, email)
	resetAttempts, err = _GetPasswordResetAttempts(tx, email)
	if err != nil {
		return err, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
	}
	if time.Now().After(resetAttempts.AttemptsBanExpiresAt) {
		resetAttempts.NumAttempts = 0
	}
	userResult := tx.Raw("SELECT * FROM users WHERE email = ? FOR UPDATE", email).Scan(&user)
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
			tokenDelete := tx.Exec("DELETE FROM refresh_tokens WHERE user_id = ?", user.ID)
			if tokenDelete.Error != nil {
				return tokenDelete.Error, utils.GENERIC_PASSWORD_RESET_ERROR
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
		errorMessage := utils.GenerateBanMessage(resetAttempts.AttemptsBanExpiresAt)
		return errors.New(errorMessage), errorMessage
	}
}

func ReplaceRefreshToken(displayName, oldTokenString, newTokenString string) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	var user models.User
	var refreshToken models.RefreshToken
	tx.Raw("SELECT * FROM users WHERE display_name = ?", displayName).Scan(&user)
	tokenResult := tx.Raw(
		"SELECT * FROM refresh_tokens WHERE token_string = ? AND user_id = ? FOR UPDATE", 
		oldTokenString, 
		user.ID,
	).Scan(&refreshToken)
	if tokenResult.Error != nil {
		return tokenResult.Error, utils.SERVER_DOWN
	}
	tokenExists := tokenResult.RowsAffected > 0
	refreshToken.TokenString = newTokenString
	if tokenExists {
		updateResult := tx.Save(&refreshToken)
		if updateResult.Error != nil {
			return updateResult.Error, utils.SERVER_DOWN
		}
	}
	tx.Commit()
	if tokenExists {
		return nil, "";
	}
	return errors.New(utils.JWT_TOKEN_PARSING_ERROR), utils.JWT_TOKEN_PARSING_ERROR;
}

func UpdateDisplayName(email, newDisplayName string) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	result := tx.Exec("UPDATE users SET display_name = ? WHERE email = ?", newDisplayName, email)
	if result.Error != nil {
		return result.Error, utils.SERVER_DOWN
	}
	tx.Commit()
	return nil, ""
}

func _GetLoginAttempts(tx *gorm.DB, email string) (models.LoginAttempts, error) {
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

func _GetPasswordResetAttempts(tx *gorm.DB, email string) (models.PasswordResetAttempts, error) {
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