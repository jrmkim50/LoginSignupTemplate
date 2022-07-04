package utils

// environment variables
const DBUSER = "DBUSER"
const DBPASS = "DBUSER"
const DBNAME = "DBNAME"
const JWT_SECRET_KEY = "JWT_SECRET_KEY"

// error messages
const GORM_ERR_CODE_DUPLICATE_KEY = "Error 1062"
const GENERIC_SIGNUP_ERROR = "We had some trouble signing you up. Please try again!"
const EMAIL_TAKEN_SIGNUP_ERROR = "Someone might have signed up with that email before. Please try logging in!"
const DISPLAY_NAME_TAKEN_SIGNUP_ERROR = "Someone is already using that display name! Please choose a different one!"
const GENERIC_LOGIN_ERROR = "We had some trouble logging you in. Please try again!"
const GENERIC_PASSWORD_RESET_REQUEST_ERROR = "We had some trouble getting you a verification code. Please try again!"
const GENERIC_PASSWORD_RESET_ERROR = "We had some trouble resetting your password. Please try again!"
const GENERIC_RATE_LIMIT_ERROR = "We had some trouble getting you a verification code. Please try again!"

// ban durations
const MAX_NUM_PASS_RESET_CODES = 10
const MAX_NUM_PASS_RESET_ATTEMPTS = 3
const MAX_NUM_LOGIN_ATTEMPTS = 3

const REFRESH_TOKEN_DURATION = 7
const ACCESS_TOKEN_DURATION = 15
const CODE_DURATION = 20

const LOGIN_BAN_DURATION = 10
const RESET_PASSWORD_REQUEST_BAN_DURATION = 10