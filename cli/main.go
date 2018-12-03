package main

import (
	"fmt"
	"github.com/dgraph-io/badger"
	"github.com/docopt/docopt-go"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"os"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}
}

func main() {
	usage := `GALP.

Usage:
  galp user add <name> <password>
  galp user check <name> <password>
  galp user delete <name>
  galp user show
  galp -h | --help
  galp --version

Options:
  -h --help     Show this screen.
  --version     Show version.`

	args, _ := docopt.ParseArgs(usage, nil, "0.0.1")
	path := getenv("DB_PATH", "galp.db")
	opts := badger.DefaultOptions
	opts.Dir = path
	opts.ValueDir = path
	db, err := badger.Open(opts)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer db.Close()

	if args["user"].(bool) {
		if args["show"].(bool) {
			err := db.View(func(txn *badger.Txn) error {
				opts := badger.DefaultIteratorOptions
				opts.PrefetchSize = 10
				it := txn.NewIterator(opts)
				defer it.Close()
				for it.Rewind(); it.Valid(); it.Next() {
					item := it.Item()
					k := item.Key()
					v, err := item.ValueCopy(nil)
					if err != nil {
						return err
					}
					fmt.Printf("%s:%s\n", k, v)
				}
				return nil
			})
			if err != nil {
				fmt.Println("Listing error: ", err.Error())
				return
			}
			return
		}
		nm := args["<name>"].(string)
		if args["delete"].(bool) {
			err = delKey(db, nm)
			if err != nil {
				fmt.Println("Deletion failed: ", err.Error())
				return
			}
			fmt.Println("Deleted")
			return
		}
		storedHash, existErr := getVal(db, nm)
		notFound := existErr == badger.ErrKeyNotFound
		pw := args["<password>"].(string)
		if args["add"].(bool) {
			if !notFound {
				fmt.Println("User already existed")
				return
			}
			err = updateVal(db, nm, pwdHashing(pw))
			if err != nil {
				fmt.Println("Create user failed: ", err.Error())
				return
			}
			fmt.Println("User created")
			return
		}
		if args["check"].(bool) {
			if err := bcrypt.CompareHashAndPassword(storedHash, []byte(pw)); err != nil {
				fmt.Println("Incorrect password")
				return
			}
			fmt.Println("Success")
			return
		}
	}
}

func updateVal(db *badger.DB, key string, val string) error {
	txn := db.NewTransaction(true)
	defer txn.Discard()
	err := txn.Set([]byte(key), []byte(val))
	if err != nil {
		return err
	}

	return txn.Commit()
}

func getVal(db *badger.DB, key string) ([]byte, error) {
	var valCopy []byte
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		valCopy, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return nil
	})

	return valCopy, err
}

func delKey(db *badger.DB, key string) error {
	txn := db.NewTransaction(true)
	defer txn.Discard()
	err := txn.Delete([]byte(key))
	if err != nil {
		return err
	}

	return txn.Commit()
}

func pwdHashing(pwd string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.MinCost)
	if err != nil {
		fmt.Println(err.Error())
		return ""
	}

	return string(hash)
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}
