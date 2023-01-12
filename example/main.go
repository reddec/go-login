package main

import (
	"fmt"
	"log"
	"net/http"

	login "github.com/reddec/go-login"
)

func loginFunc(writer http.ResponseWriter, r *http.Request, cred login.UserPassword) error {
	log.Printf("%+v", cred)
	ok := cred.User == "admin" && cred.Password == "admin" // user proper login and validation
	if !ok {
		return fmt.Errorf("username or password is incorrect")
	}
	//TODO: use sessions/JWT/cookies and mark following requests as authorized
	return nil
}

func main() {
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("<html><body><h1>Home</h1><br/><a href='/login'>Login</a></body></html>"))
	})
	http.Handle("/login", login.New[login.UserPassword](loginFunc, login.Log(func(err error) {
		log.Println(err)
	})))
	panic(http.ListenAndServe("127.0.0.1:8080", nil))
}
