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
	var err error
	result := tx.Raw("SELECT * FROM login_attempts WHERE email = ? FOR UPDATE", email).Scan(&loginAttempts)
	if result.Error != nil {
		return accessToken, refreshToken, result.Error, utils.GENERIC_LOGIN_ERROR
	}
	if result.RowsAffected == 0 {
		loginAttempts = models.LoginAttempts{
			Email: email,
			NumAttempts: 0,
			BanExpiresAt: time.Now(),
		}
		createResult := tx.Create(&loginAttempts)
		if createResult.Error != nil {
			return accessToken, refreshToken, createResult.Error, utils.GENERIC_LOGIN_ERROR
		}
	}
	if time.Now().After(loginAttempts.BanExpiresAt) && loginAttempts.NumAttempts == utils.MAX_NUM_LOGIN_ATTEMPTS {
		loginAttempts.NumAttempts = 0
	}
	result = tx.Raw("SELECT * FROM users WHERE email = ?", email).Scan(&user)
	if result.Error != nil {
		return accessToken, refreshToken, result.Error, utils.GENERIC_LOGIN_ERROR
	}
	passwordCompare := utils.ComparePasswords(user.PasswordHash, password)
	loginValid := loginAttempts.NumAttempts < utils.MAX_NUM_LOGIN_ATTEMPTS && result.RowsAffected > 0 && passwordCompare != nil
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
	updateResult := tx.Exec(
		"UPDATE login_attempts SET num_attempts = ?, ban_expires_at = ? WHERE email = ?", 
		loginAttempts.NumAttempts, 
		loginAttempts.BanExpiresAt, 
		loginAttempts.Email,
	)
	if updateResult.Error != nil {
		return refreshToken, accessToken, updateResult.Error, utils.GENERIC_LOGIN_ERROR
	}
	tx.Commit()
	if loginValid {
		return accessToken, refreshToken, nil, ""
	} else {
		if loginAttempts.NumAttempts == utils.MAX_NUM_LOGIN_ATTEMPTS {
			errorMessage := "Login unsuccessful. " + utils.GenerateBanMessage(loginAttempts.BanExpiresAt)
			return refreshToken, accessToken, errors.New(errorMessage), errorMessage
		}
		return refreshToken, accessToken, errors.New("Login unsuccessful."), utils.GENERIC_LOGIN_ERROR
	}
}

func CreateUser(email, displayName, passwordHash string, refreshToken utils.JWT_TOKEN) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	tokenObject := models.RefreshToken{
		TokenString: refreshToken.TokenString,
		TokenExpiresAt: refreshToken.ExpireTime,
	}
	result := tx.Create(&tokenObject)
	if result.Error != nil {
		return result.Error, utils.GENERIC_SIGNUP_ERROR
	}
	user := models.User{
		Email: email, 
		PasswordHash: passwordHash, 
		DisplayName: displayName,
		PhoneVerified: false,
	}
	result = tx.Create(&user)
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
	tx.Commit()
	return nil, ""
}

func CreatePasswordResetCode(email string) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	var resetAttempts models.PasswordResetAttempts
	var user models.User
	result := tx.Raw("SELECT * FROM password_reset_attempts WHERE email = ? FOR UPDATE", email).Scan(&resetAttempts)
	if result.Error != nil {
		return result.Error, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
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
			return createResult.Error, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
		}
	}
	if time.Now().After(resetAttempts.RequestsBanExpiresAt) && resetAttempts.NumRequests == utils.MAX_NUM_PASS_RESET_CODES {
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
	updateResult := tx.Exec(
		"UPDATE password_reset_attempts SET num_requests = ?, requests_ban_expires_at = ? WHERE email = ?", 
		resetAttempts.NumRequests, 
		resetAttempts.RequestsBanExpiresAt, 
		resetAttempts.Email,
	)
	if updateResult.Error != nil {
		return updateResult.Error, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
	}
	tx.Commit()
	if resetAttempts.NumRequests < utils.MAX_NUM_PASS_RESET_CODES {
		return nil, ""
	} else {
		errorMessage := "Password reset request unsuccessful. " + utils.GenerateBanMessage(resetAttempts.RequestsBanExpiresAt)
		return errors.New(errorMessage), errorMessage
	}
}

func VerifyPasswordResetCode(email, code, passwordHash string) (error, string) {
	tx := DB.Begin()
	defer tx.Rollback()
	var resetAttempts models.PasswordResetAttempts
	var user models.User
	var resetCode models.PasswordResetCode
	result := tx.Raw("SELECT * FROM password_reset_attempts WHERE email = ? FOR UPDATE", email).Scan(&resetAttempts)
	if result.Error != nil {
		return result.Error, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
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
			return createResult.Error, utils.GENERIC_PASSWORD_RESET_REQUEST_ERROR
		}
	}
	if time.Now().After(resetAttempts.AttemptsBanExpiresAt) && resetAttempts.NumAttempts == utils.MAX_NUM_PASS_RESET_ATTEMPTS {
		resetAttempts.NumAttempts = 0
	}
	userResult := tx.Raw("SELECT * FROM users WHERE email = ? FOR UPDATE", email).Scan(&user)
	if userResult.Error != nil {
		return userResult.Error, utils.GENERIC_PASSWORD_RESET_ERROR
	}
	userExists := userResult.RowsAffected > 0
	codeErr := tx.Model(&user).Where("code = ?", code).Association("PasswordResetCode").Find(&resetCode)
	codeExists := userExists && codeErr != nil
	if resetAttempts.NumAttempts < utils.MAX_NUM_PASS_RESET_ATTEMPTS {
		resetAttempts.AttemptsBanExpiresAt = time.Now().Add(time.Minute * utils.RESET_PASSWORD_REQUEST_BAN_DURATION)
		if codeExists {
			resetAttempts.NumAttempts = 0
			user.PasswordHash = passwordHash
			updateResult := tx.Save(&user)
			if updateResult.Error != nil {
				return updateResult.Error, utils.GENERIC_PASSWORD_RESET_ERROR
			}
		} else {
			resetAttempts.NumAttempts++
		}
	}
	updateResult := tx.Save(&resetAttempts)
	if updateResult.Error != nil {
		return updateResult.Error, utils.GENERIC_PASSWORD_RESET_ERROR
	}
	tx.Commit()
	if resetAttempts.NumRequests < utils.MAX_NUM_PASS_RESET_CODES {
		return nil, ""
	} else {
		errorMessage := "Password reset attempt unsuccessful. " + utils.GenerateBanMessage(resetAttempts.AttemptsBanExpiresAt)
		return errors.New(errorMessage), errorMessage
	}
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