package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/webauthn"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	webAuthn     *webauthn.WebAuthn
	userDB       *userdb
	sessionStore *session.Store
	err          error
)

func main() {
	r := chi.NewRouter()

	// middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)

	// webauthn configuration
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Nao50 WebAuthn Example",    // Display Name for your site
		RPID:          "localhost",                 // Generally the FQDN for your site
		RPOrigin:      "http://localhost:5051",     // The origin URL for WebAuthn requests
		RPIcon:        "http://localhost/logo.png", // Optional icon URL for your site
	})
	if err != nil {
		fmt.Println(err)
	}

	// new stores
	userDB = newUserDB()
	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	// handler
	r.Get("/register/begin/{username}", BeginRegistration)
	r.Post("/register/result/{username}", ResultRegistration)
	r.Get("/login/begin/{username}", BeginLogin)
	r.Post("/login/result/{username}", ResultLogin)

	r.Handle("/", http.FileServer(http.Dir("./static")))

	log.Println("starting server at :5051")
	http.ListenAndServe(":5051", r)
}
