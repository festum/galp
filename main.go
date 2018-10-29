package main

import (
	"crypto/tls"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/joho/godotenv"
	"gopkg.in/ldap.v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
	"github.com/rs/zerolog/log"
)

const (
	TMPL_INDEX = `
<html>
<head>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/3.0.3/normalize.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/skeleton/2.0.4/skeleton.min.css">
  <style>form{margin-top: 50px;}
  </style>
</head>
<body>
<div class="container">
<form method="post" action="/api/login">
  <div class="row">
    <div class="five columns">
      <label for="Email">Email</label>
      <input class="u-full-width" type="text" placeholder="Email" name="email">
    </div>
    <div class="five columns">
      <label for="Username">Password</label>
      <input class="u-full-width" type="password" placeholder="Password" name="password">
    </div>
    <div class="two columns">
      <label for="exampleEmailInput">&nbsp;</label>
      <input class="button-primary" type="submit" value="Login">
    </div>
  </div>
</form>
</div>
</body>
</html>
`
)


type app struct{
	IsDev        bool          `env:"DEV_MODE" envDefault:true`
	Address      string        `env:"APP_ADDR" envDefault:"80"`
	JWT          string        `env:"APP_JWT_KEY"`
	JWTAuth 	 *jwtauth.JWTAuth
	Services     []string      `env:"EXPOSE_SERVICES" envSeparator:";"`
}


func init() {
	err := godotenv.Load()
	if err != nil {
		log.Info().Msg("Error loading .env file")
	}
}

func main() {
	a := app{}
	if err := env.Parse(&a); err != nil {
		log.Info().Msg("%+v\n" + err.Error())
	}
	a.JWTAuth = jwtauth.New("HS256", []byte(a.JWT), nil)

	http.ListenAndServe(a.Address, a.router())
}

func (a app)router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)

	//Private
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(a.JWTAuth))
		r.Use(validateToken)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			w.Write([]byte(fmt.Sprintf("Protected area. Hi %v", claims["user_id"])))
		})
	})
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(a.JWTAuth))
		r.Use(validateToken)
		r.Use(a.mapRouter)

		r.Get("/r/*", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			w.Write([]byte(fmt.Sprintf("protected area. hi %v", claims["user_id"])))
		})
	})

	//Public
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Welcome to go-ldap-auth-proxy"))
		})
		r.Post("/api/login", a.loginHandler)
	})

	return r
}


func (a app)loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	pass := r.FormValue("password")

	if email == "" || pass == "" {
		http.Error(w, "Please enter correct email and password", 400)
		return
	}
	l := ldapauth{}
	if err := env.Parse(&l); err != nil {
		log.Debug().Msg( err.Error())
	}
	if !l.authVerify(email, pass){
		http.Error(w, "Unauthorized", 401)
		return
	}
	_, tokenString, _ := a.JWTAuth.Encode(jwt.MapClaims{"user_id": email})
	addCookie(w, "jwt", tokenString)

	http.Redirect(w, r, r.Header.Get("Referer"), 302)
}

func (a app) mapRouter(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		appIndex := 2
		reroute := strings.Split(r.URL.Path, "/")[appIndex] // Path supposed to be /r/[serviceAp]p/[subRoute]

		tURLPlain := a.getService(reroute)
		if len(tURLPlain) <1 {
			http.Error(w, fmt.Sprintf("Service not found for %s. Please contact system admin.", reroute), 404)
			return
		}

		tURL, err := url.Parse(tURLPlain)
		if err!=nil {
			http.Error(w, "Incorrect URL format. Please check the settings.", 400)
			return
		}

		r.URL.Host = tURL.Host
		r.URL.Scheme = tURL.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = tURL.Host
		r.URL.Path = strings.Join(strings.Split(r.URL.Path, "/")[appIndex+1:], "/")

		httputil.NewSingleHostReverseProxy(tURL).ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (a app) getService(serviceName string) string{
	for _, p := range a.Services {
		pair := strings.Split(p, "=")
		log.Debug().Msg(p)
		if pair[0] == serviceName {
			return pair[1]
		}
	}
	return ""
}

func validateToken(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("jwt")
		if err != nil || token == nil {
			log.Debug().Msg(err.Error())
			delCookie(w,"jwt")
			w.Write([]byte(TMPL_INDEX))
			return
		}

		_, claims, _ := jwtauth.FromContext(r.Context())
		if claims["user_id"] == nil{
			delCookie(w,"jwt")
			w.Write([]byte(TMPL_INDEX))
			return
		}

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

type User struct {
	Email string  `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}


func addCookie(w http.ResponseWriter, name string, value string) {
	expire := time.Now().AddDate(0, 0, 1)
	c := http.Cookie{
		Name:    name,
		Value:   value,
		Path:     "/",
		Expires: expire,
	}
	http.SetCookie(w, &c)
}

func delCookie(w http.ResponseWriter, name string){
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires: time.Unix(0, 0),
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

type ldapauth struct{
	Host string `env:"LDAP_HOST"`
	Port string `env:"LDAP_PORT" envDefault:"636"`
	Protocol string `env:"LDAP_PROTOCOL" envDefault:"tcp"`
	SkipVerify bool `env:"LDAP_SKIP_VERIFY" envDefault:true`
	BindDN string `env:"LDAP_BIND_DN"`
	BindPassword string `env:"LDAP_BIND_PASSWORD"`
	UserBase string `env:"LDAP_USER_BASE"`
	Filter string `env:"LDAP_FILTER"`
	AttributeMail string `env:"LDAP_ATTRIBUTE_MAIL" envDefault:"mail"`
	AttributesInBind bool `env:"LDAP_ATTRIBUTES_IN_BIND" envDefault:false`
}

func (la ldapauth) authVerify(email, password string) bool{
	tlsConfig := &tls.Config{InsecureSkipVerify: la.SkipVerify}
	l, err := ldap.DialTLS(la.Protocol, fmt.Sprintf("%s:%s", la.Host, la.Port), tlsConfig)
	if err != nil {
		log.Info().Msg(err.Error())
		return false
	}
	defer func() {
		l.Close()
		log.Debug().Msg("LDAP server disconnected.")
	}()

	err = l.Bind(la.BindDN, la.BindPassword)
	if err != nil {
		log.Debug().Msg(err.Error())
		return false
	}
	log.Debug().Msg("LDAP server logged in.")

	sr, err := l.Search(la.searchQuery(email))
	if err != nil {
		log.Debug().Msg(err.Error())
	}
	if len(sr.Entries) < 1 {
		log.Debug().Msg("User does not exist")
		return false
	}
	userdn := sr.Entries[0].DN
	err = l.Bind(userdn, password)
	if err != nil {
		log.Debug().Msg(err.Error())
		return false
	}

	return true
}

func (la ldapauth) searchQuery(username string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		la.UserBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(la.Filter, username),
		[]string{"dn"},
		nil,
	)
}
