package galp

import (
	"bytes"
	"github.com/caarlos0/env"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

func init() {
	os.Setenv("DEV_MODE", "true")
	os.Setenv("APP_ADDR", "80")
	os.Setenv("APP_JWT_KEY", "./galp.key")
	os.Setenv("EXPOSE_SERVICES", "app1=http://127.0.0.1:3000;app2=http://127.0.0.1:8000")
	os.Setenv("LDAP_PORT", "636")
	os.Setenv("LDAP_PROTOCOL", "tcp")
	os.Setenv("LDAP_SKIP_VERIFY", "true")
	os.Setenv("LDAP_FILTER", "((mail=%s))")
}

func TestApp(t *testing.T) {
	a := App{}
	if err := env.Parse(&a); err != nil {
		t.Error("Parse variables from environment error")
	}

	data := url.Values{}
	data.Set("email2", "test")
	data.Add("password", "test")

	r := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(data.Encode()))
	w := httptest.NewRecorder()

	a.loginHandler(w, r)
	if w.Code != http.StatusBadRequest {
		t.Error("Not check content")
	}

}
