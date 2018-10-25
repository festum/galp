package main

import (
	"crypto/tls"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/joho/godotenv"
	"gopkg.in/ldap.v2"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/jwtauth"
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
		log.Fatal("Error loading .env file")
	}
}

func main() {
	a := app{}
	if err := env.Parse(&a); err != nil {
		log.Fatalln("%+v\n", err)
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
		r.Use(ValidateToken)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			w.Write([]byte(fmt.Sprintf("protected area. hi %v", claims["user_id"])))
		})
	})

	//Public
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Welcome to go-ldap-auth-proxy"))
		})
		r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(TMPL_INDEX))
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
		log.Println("%+v\n", err)
	}
	if !l.authVerify(email, pass){
		http.Error(w, "Unauthorized", 401)
		return
	}
	_, tokenString, _ := a.JWTAuth.Encode(jwt.MapClaims{"user_id": email})
	addCookie(w, "jwt", tokenString)

	//TODO: proxy path
	http.Redirect(w, r, "/admin", 302)

}

func ValidateToken(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("jwt")
		if err != nil || token == nil {
			log.Println(err.Error())
			delCookie(w,"jwt")
			http.Redirect(w, r, "/login", 302)
			return
		}

		_, claims, _ := jwtauth.FromContext(r.Context())
		if claims["user_id"] == nil{
			delCookie(w,"jwt")
			http.Redirect(w, r, "/login", 302)
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
	log.Println(la)
	tlsConfig := &tls.Config{InsecureSkipVerify: la.SkipVerify}
	l, err := ldap.DialTLS(la.Protocol, fmt.Sprintf("%s:%s", la.Host, la.Port), tlsConfig)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer func() {
		l.Close()
		log.Println("LDAP server disconnected.")
	}()

	err = l.Bind(la.BindDN, la.BindPassword)
	if err != nil {
		log.Println(err)
		return false
	}
	log.Println("LDAP server logged in.")

	sr, err := l.Search(la.searchQuery(email))
	if err != nil {
		log.Println(err)
	}
	if len(sr.Entries) < 1 {
		log.Println("User does not exist")
		return false
	}
	userdn := sr.Entries[0].DN
	err = l.Bind(userdn, password)
	if err != nil {
		log.Println(err)
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
