package main

import (
	"github.com/shoppingapp/apiv1/dbhelper"
	"github.com/shoppingapp/apiv1/routes"
	"os"
	"log"
	"net/http"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

func main() {
	// Setting up environment variables
	err := godotenv.Load()
	if err != nil {
    		log.Fatal(err)
	}
	// Setting up logs
	file, err := os.OpenFile("logs.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)
	// Setting up database
	err = dbhelper.OpenDB()
	if err != nil {
		log.Fatal(err)
	}
	err = dbhelper.InitDB()
	if err != nil {
		log.Fatal(err)
	}
	// Opening the webserver
	r := mux.NewRouter()
	r.StrictSlash(true)
	routes.CreateRoutes(r)
	http.ListenAndServe(":5005", r)
}
