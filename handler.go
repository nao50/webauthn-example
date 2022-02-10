package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/duo-labs/webauthn/protocol"

	"github.com/go-chi/chi/v5"
)

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		log.Println("username required")
		jsonResponse(w, "username required", http.StatusBadRequest)
		return
	}

	user, err := userDB.GetUser(username)
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	options, sessionData, err := webAuthn.BeginRegistration(user, registerOptions)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)

}

func ResultRegistration(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		log.Println("username required")
		jsonResponse(w, "username required", http.StatusBadRequest)
		return
	}
	// get user
	user, err := userDB.GetUser(username)
	if err != nil {
		log.Println("ResultRegistration GetUser fail: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Println("ResultRegistration GetWebauthnSession fail: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		log.Println("ResultRegistration FinishRegistration fail: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// parsedResponse, _ := protocol.ParseCredentialCreationResponse(r)

	// parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	// if err != nil {
	// 	log.Println("ResultRegistration ParseCredentialCreationResponseBody fail: ", err)
	// 	jsonResponse(w, err.Error(), http.StatusBadRequest)
	// 	return
	// }
	// credential, err := webAuthn.CreateCredential(user, sessionData, parsedResponse)
	// if err != nil {
	// 	log.Println("ResultRegistration CreateCredential fail: ", err)
	// 	jsonResponse(w, err.Error(), http.StatusBadRequest)
	// 	return
	// }

	user.AddCredential(*credential)

	jsonResponse(w, "Registration Success", http.StatusOK)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		log.Println("username required")
		jsonResponse(w, "username required", http.StatusBadRequest)
		return
	}
	// get user
	user, err := userDB.GetUser(username)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func ResultLogin(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	if username == "" {
		log.Println("username required")
		jsonResponse(w, "username required", http.StatusBadRequest)
		return
	}
	// get user
	user, err := userDB.GetUser(username)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Println("ResultLogin GetWebauthnSession Fail: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	credential, err := webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		log.Println("ResultLogin FinishLogin Fail: ", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("credential: %+v\n", credential)

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
