package galp

import (
	"crypto/tls"
	"fmt"
	"github.com/dgraph-io/badger"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/ldap.v2"

	"github.com/rs/zerolog/log"
)

type ldapauth struct {
	Host         string `env:"LDAP_HOST"`
	Port         string `env:"LDAP_PORT" envDefault:"636"`
	Protocol     string `env:"LDAP_PROTOCOL" envDefault:"tcp"`
	SkipVerify   bool   `env:"LDAP_SKIP_VERIFY" envDefault:"true"`
	BindDN       string `env:"LDAP_BIND_DN"`
	BindPassword string `env:"LDAP_BIND_PASSWORD"`
	UserBase     string `env:"LDAP_USER_BASE"`
	Filter       string `env:"LDAP_FILTER" envDefault:"((mail=%s))"`

	DBPath string `env:"DB_PATH" envDefault:"galp.db"`
}

func (la ldapauth) authVerify(email, password string) bool {
	tlsConfig := &tls.Config{InsecureSkipVerify: la.SkipVerify}
	l, err := ldap.DialTLS(la.Protocol, fmt.Sprintf("%s:%s", la.Host, la.Port), tlsConfig)
	if err != nil {
		log.Error().Msg(err.Error())
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
		log.Error().Msg(err.Error())
		return false
	}
	defer db.Close()
	var pwHash []byte
	if err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(email))
		if err != nil {
			return err
		}
		pwHash, err = item.ValueCopy(nil)
		if  err != nil {
			return err
		}
		return nil
	}); err != nil {
		log.Info().Msg(err.Error())
		return false
	}
	if err := bcrypt.CompareHashAndPassword(pwHash, []byte(password)); err == nil {
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
