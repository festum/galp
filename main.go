package main

import (
	"crypto/tls"
	"fmt"
	"github.com/caarlos0/env"
	"github.com/dgraph-io/badger"
	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/ldap.v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

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
	Services     []string      `env:"EXPOSE_SERVICES" envSeparator:";"`
	JWT          string        `env:"APP_JWT_KEY"`
	JWTTTL       int           `env:"APP_JWT_TTL" envDefault:"72"`
	JWTAuth 	 *jwtauth.JWTAuth
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

func (a app) router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)

	//Private
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(a.JWTAuth))
		r.Use(a.validateToken)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fmt.Sprintf("Protected area. Hi %v", r.Header.Get("GALP_UID"))))
		})
	})
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(a.JWTAuth))
		r.Use(a.validateToken)
		r.Use(a.mapRouter)

		r.HandleFunc("/r/*", func(w http.ResponseWriter, r *http.Request) {})
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


func (a app) loginHandler(w http.ResponseWriter, r *http.Request) {
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
	a.addJWT(w, email)

	http.Redirect(w, r, r.Header.Get("Referer"), 302)
}

func (a app) addJWT(w http.ResponseWriter, id string){
	exp := time.Now().Add(time.Hour * time.Duration(a.JWTTTL)).Unix()
	_, tokenString, _ := a.JWTAuth.Encode(jwt.MapClaims{
		"id": id,
		"exp": exp,
	})
	addCookie(w, "jwt", tokenString)
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

func (a app) validateToken(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("jwt")
		if err != nil || token == nil {
			log.Debug().Msg(err.Error())
			delCookie(w,"jwt")
			w.Write([]byte(TMPL_INDEX))
			return
		}
		_, claims, _ := jwtauth.FromContext(r.Context())
		if claims["id"] == nil {
			delCookie(w,"jwt")
			w.Write([]byte(TMPL_INDEX))
			return
		}
		
		id := claims["id"].(string)
		a.addJWT(w, id)// Extend expiry
		r.Header.Set("GALP_UID", id)
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func addCookie(w http.ResponseWriter, name string, value string) {
	exp := time.Now().AddDate(0, 0, 7)
	c := http.Cookie{
		Name:    name,
		Value:   value,
		Path:     "/",
		Expires: exp,
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

	DBPath       string        `env:"DB_PATH" envDefault:"galp.db"`
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
	if len(sr.Entries) > 0 {
		if err := l.Bind(sr.Entries[0].DN, password); err == nil {
			log.Debug().Msg("Login through LDAP")
			return true
		}
	}

	opts := badger.DefaultOptions
	opts.Dir = la.DBPath
	opts.ValueDir = la.DBPath
	db, err := badger.Open(opts)
	if err != nil {
		log.Info().Msg(err.Error())
		return false
	}
	defer db.Close()
	var pwHash []byte
	if err := db.View(func(txn *badger.Txn) error {
			item, err := txn.Get([]byte(email))
			if err != nil {
				return err
			}
			if err := item.Value(func(val []byte) error {
				pwHash = append([]byte{}, val...)
				return nil
			}); err != nil {
				return err
			}
			return nil
		}); err != nil {
		log.Info().Msg(err.Error())
		return false
	}
	if err := bcrypt.CompareHashAndPassword(pwHash, []byte(password)); err == nil{
		log.Debug().Msg("Login through DB")
		return true
	}

	return false
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


func pwdIsValid(hashedPwd string, plainPwd []byte) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPwd), plainPwd); err != nil {
		return false
	}
	return true
}