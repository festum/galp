package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/caarlos0/env"
	"github.com/festum/galp/core"
	"github.com/go-chi/jwtauth"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}
}

func main() {
	a := galp.App{}
	if err := env.Parse(&a); err != nil {
		fmt.Printf("%s\n",  err.Error())
	}
	pk, err := ioutil.ReadFile(a.JWTPKPath)
	if err != nil {
		fmt.Printf("Error reading private key %s\n",  err.Error())
		return
	}
	a.JWTAuth = jwtauth.New("HS256", []byte(pk), nil)

	http.ListenAndServe(a.Address, a.Router())
}
