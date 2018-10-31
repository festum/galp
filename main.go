package main

import (
	"github.com/rs/zerolog"
	"io/ioutil"
	"net/http"

	"github.com/caarlos0/env"
	"github.com/festum/galp/core"
	"github.com/go-chi/jwtauth"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

func init() {
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	err := godotenv.Load()
	if err != nil {
		log.Error().Msg("Error loading .env file")
	}
}

func main() {
	a := galp.App{}
	if err := env.Parse(&a); err != nil {
		log.Info().Msg(err.Error())
	}
	pk, err := ioutil.ReadFile(a.JWTPKPath)
	if err != nil {
		log.Info().Msg("Error reading private key " + err.Error())
		return
	}
	a.JWTAuth = jwtauth.New("HS256", []byte(pk), nil)

	http.ListenAndServe(a.Address, a.Router())
}
