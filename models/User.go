package models

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	gorm.Model
	Email string `gorm:"unique"`
	PasswordHash string
	DisplayName string `gorm:"unique"`
	PhoneVerified bool
}

type LoginAttempts struct {
	gorm.Model
	Email string `gorm:"unique"`
	NumAttempts uint
	BanExpiresAt time.Time
}

type PasswordResetAttempts struct {
	gorm.Model
	Email string `gorm:"unique"`
	NumRequests uint
	RequestsBanExpiresAt time.Time
	NumAttempts uint
	AttemptsBanExpiresAt time.Time
}

type PasswordResetCode struct {
	gorm.Model
	UserID uint
	User User
	Code string
	CodeExpiresAt time.Time
}

type RefreshToken struct {
	gorm.Model
	TokenString string
	TokenExpiresAt time.Time
}