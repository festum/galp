package galp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/caarlos0/env"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/jwtauth"
	"github.com/rs/zerolog"
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
	IsDev          bool     `env:"DEV_MODE" envDefault:"true"`
	Address        string   `env:"APP_ADDR" envDefault:"80"`
	Services       []string `env:"EXPOSE_SERVICES" envSeparator:";"`
	HeaderIDKey    string   `env:"HEADER_ID_KEY" envDefault:"GALP-UID"`
	JWTTTL         int      `env:"APP_JWT_TTL" envDefault:"72"`
	JWTPKPath      string   `env:"APP_JWT_KEY" envDefault:"./galp.key"`
	JWTAuth        *jwtauth.JWTAuth
	AllowedOrigins []string `env:"ALLOWED_ORIGINS" envSeparator:"," envDefault:"*"`
	AllowedMethods []string `env:"ALLOWED_METHODS" envSeparator:"," envDefault:"GET,POST,PUT,DELETE,OPTIONS"`
	AllowedHeaders []string `env:"ALLOWED_HEADERS" envSeparator:"," envDefault:"Accept,Authorization,Content-Type,X-CSRF-Token"`
	ExposedHeaders []string `env:"EXPOSED_HEADERS" envSeparator:"," envDefault:"Link,Authorization"`
	MaxAge         int      `env:"MAX_AGE" envDefault:"300"` // Maximum value not ignored by any of major browsers
}

func (a App) init() {
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	if a.IsDev {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

//Router Chi router
func (a App) Router() http.Handler {
	cx := cors.New(cors.Options{
		AllowedOrigins:   a.AllowedOrigins,
		AllowedMethods:   a.AllowedMethods,
		AllowedHeaders:   a.AllowedHeaders,
		ExposedHeaders:   a.ExposedHeaders,
		AllowCredentials: true,
		MaxAge:           a.MaxAge,
	})
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(cx.Handler)

	//Private
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(a.JWTAuth))
		r.Use(a.validateToken)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(fmt.Sprintf("Protected area. Hi %v", a.HeaderIDKey)))
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
	var email, pass string
	isAPI := r.Header.Get("Content-type") == "application/json"
	if isAPI {
		u := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}
		if r.Body == nil {
			http.Error(w, "Please send a request body", 400)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		email = u.Email
		pass = u.Password
	} else {
		email = r.FormValue("email")
		pass = r.FormValue("password")
	}
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
	w.Header().Set("User-ID", email)

	if isAPI {
		w.WriteHeader(200)
		return
	}
	http.Redirect(w, r, r.Header.Get("Referer"), 302)
}

func (a App) addJWT(w http.ResponseWriter, id string) {
	exp := time.Now().Add(time.Hour * time.Duration(a.JWTTTL)).Unix()
	_, tokenString, _ := a.JWTAuth.Encode(jwt.MapClaims{
		"id":  id,
		"exp": exp,
	})
	addCookie(w, "jwt", tokenString)
	w.Header().Set("Authorization", fmt.Sprintf("BEARER %s", tokenString))
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

		rp := &httputil.ReverseProxy{
			Director: func(r *http.Request) {
				r.URL.Scheme = tURL.Scheme
				r.URL.Host = tURL.Host
				r.URL.Path = strings.Join(strings.Split(r.URL.Path, "/")[appIndex+1:], "/")
				r.Header["X-Forwarded-Host"] = []string{r.Header.Get("Host")}
			},
		}
		w.Header().Set("X-Forwarded-For", r.Header.Get("Host"))
		w.Header().Del("Access-Control-Allow-Origin")
		rp.ServeHTTP(w, r)
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
		_, claims, _ := jwtauth.FromContext(r.Context())
		if claims["id"] == nil {
			delCookie(w, "jwt")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(TMPLIndex))
			return
		}

		id := claims["id"].(string)
		a.addJWT(w, id) // Extend expiry
		r.Header.Set(a.HeaderIDKey, id)
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
