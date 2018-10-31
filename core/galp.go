package galp

import (
	"fmt"
	"github.com/caarlos0/env"
	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog"
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
	//TMPLIndex contains HTML Template for Index
	TMPLIndex = `
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

//App grouping Chi routes and handlers
type App struct {
	IsDev     bool     `env:"DEV_MODE" envDefault:"true"`
	Address   string   `env:"APP_ADDR" envDefault:"80"`
	Services  []string `env:"EXPOSE_SERVICES" envSeparator:";"`
	JWTTTL    int      `env:"APP_JWT_TTL" envDefault:"72"`
	JWTPKPath string   `env:"APP_JWT_KEY" envDefault:"./galp.key"`
	JWTAuth   *jwtauth.JWTAuth
}

func (a App) init() {
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	if a.IsDev {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

//Router Chi router
func (a App) Router() http.Handler {
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

func (a App) loginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	pass := r.FormValue("password")

	if email == "" || pass == "" {
		http.Error(w, "Please enter correct email and password", 400)
		return
	}
	l := ldapauth{}
	if err := env.Parse(&l); err != nil {
		log.Debug().Msg(err.Error())
	}
	if !l.authVerify(email, pass) {
		http.Error(w, "Unauthorized", 401)
		return
	}
	a.addJWT(w, email)

	http.Redirect(w, r, r.Header.Get("Referer"), 302)
}

func (a App) addJWT(w http.ResponseWriter, id string) {
	exp := time.Now().Add(time.Hour * time.Duration(a.JWTTTL)).Unix()
	_, tokenString, _ := a.JWTAuth.Encode(jwt.MapClaims{
		"id":  id,
		"exp": exp,
	})
	addCookie(w, "jwt", tokenString)
}

func (a App) mapRouter(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		appIndex := 2
		reroute := strings.Split(r.URL.Path, "/")[appIndex] // Path supposed to be /r/[serviceAp]p/[subRoute]

		tURLPlain := a.getService(reroute)
		if len(tURLPlain) < 1 {
			http.Error(w, fmt.Sprintf("Service not found for %s. Please contact system admin.", reroute), 404)
			return
		}

		tURL, err := url.Parse(tURLPlain)
		if err != nil {
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

func (a App) getService(serviceName string) string {
	for _, p := range a.Services {
		pair := strings.Split(p, "=")
		log.Debug().Msg(p)
		if pair[0] == serviceName {
			return pair[1]
		}
	}
	return ""
}

func (a App) validateToken(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("jwt")
		if err != nil || token == nil {
			log.Debug().Msg(err.Error())
			delCookie(w, "jwt")
			w.Write([]byte(TMPLIndex))
			return
		}
		_, claims, _ := jwtauth.FromContext(r.Context())
		if claims["id"] == nil {
			delCookie(w, "jwt")
			w.Write([]byte(TMPLIndex))
			return
		}

		id := claims["id"].(string)
		a.addJWT(w, id) // Extend expiry
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
		Path:    "/",
		Expires: exp,
	}
	http.SetCookie(w, &c)
}

func delCookie(w http.ResponseWriter, name string) {
	c := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}
