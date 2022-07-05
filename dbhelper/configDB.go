package dbhelper

import (
	"github.com/shoppingapp/apiv1/models"
	"github.com/shoppingapp/apiv1/utils"
	"gorm.io/gorm"
	"gorm.io/driver/mysql"
	"fmt"
	"os"
)

var DB *gorm.DB

func OpenDB() error {
	var err error
	dsn := fmt.Sprintf(
		"%s:%s@tcp(127.0.0.1:3306)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		os.Getenv(utils.DBUSER),
		os.Getenv(utils.DBPASS),
		os.Getenv(utils.DBNAME),
	)
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	return err
}

func InitDB() error {
	return DB.AutoMigrate(
		&models.User{},
		&models.LoginAttempts{}, 
		&models.PasswordResetAttempts{},
		&models.PasswordResetCode{}, 
		&models.RefreshToken{},
	)
}