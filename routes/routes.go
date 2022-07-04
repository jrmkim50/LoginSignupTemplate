package routes

import (
	"github.com/gorilla/mux"
	"github.com/go-playground/validator/v10"
)
// "time"
// "golang.org/x/time/rate"

var validate *validator.Validate

// type visitor struct {
// 	limiter  *rate.Limiter
// 	lastSeen time.Time
// }

func CreateRoutes(r *mux.Router) {
	validate = validator.New()
	s := r.PathPrefix("/api/auth").Subrouter()
	AuthRouter(s)
}