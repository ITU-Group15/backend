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

	//router.Handle("/getusers", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.GetUsers))))

	router.Handle("/join", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.JoinChannel))))
	router.Handle("/create", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.CreateChannel))))
	router.Handle("/channels", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.GetChannels))))
	router.Handle("/delete/{id}", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.DeleteChannel))))

	router.Handle("/send", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.SendMessage))))
	router.Handle("/getmessages", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.GetMessages))))
	router.Handle("/search", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.SearchChannel))))
	router.Handle("/profile", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.Profile))))
	router.Handle("/changeprofile", negroni.New(negroni.HandlerFunc(handlers.AuthMiddleware), negroni.Wrap(http.HandlerFunc(handlers.ChangeProfile))))


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


