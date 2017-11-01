package main

import (
	"log"
	"net/http"
	"os"
	"fmt"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"channelx/handlers"
)

func main() {
	router := mux.NewRouter()
	n := negroni.Classic()


	router.HandleFunc("/login", handlers.LoginFunc)
	router.HandleFunc("/register", handlers.RegisterFunc)
	router.HandleFunc("/getusers", handlers.GetUsers)



	n.UseHandler(router)


	addr, err := determineListenAddress()
	if err != nil {
		log.Fatal(err)
	}
	if err := http.ListenAndServe(addr, n); err != nil {
		panic(err)
	}
}

func determineListenAddress() (string, error) {
	port := os.Getenv("PORT")
	if port == "" {
		return "", fmt.Errorf("$PORT not set")
	}
	return ":" + port, nil
}


