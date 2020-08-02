package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
	"golang.org/x/oauth2"
)

func handler(w http.ResponseWriter, r *http.Request) {
	return
}

func ssoCallback(w http.ResponseWriter, r *http.Request) {
	return
}

func BasicMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next(w, r)
}

func initRoutes() {
	fmt.Println("init routes")
	r := mux.NewRouter()

	ctx := context.Background()

	clientID := "mvc"
	clientSecret := "secret"

	provider, err := oidc.NewProvider(ctx, "http://localhost:5001")
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:5002/signin-oidc",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "api1"},
	}

	state := "code" // Don't do this in production.

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusFound)
	})

	r.HandleFunc("/signin-oidc", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Println(oauth2Token)
		fmt.Println(idToken)

		io.WriteString(w, `
		<html>
			<body>
				<h1>Login successful!</h1>
			</body>
		</html>`)

		fmt.Println("Successfully logged into snapmaster API.")

		//oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	r.HandleFunc("/signout-callback-oidc", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("logout")

		c := &http.Cookie{
			Name:    "idsrv.session",
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),

			HttpOnly: true,
		}

		http.SetCookie(w, c)

		c = &http.Cookie{
			Name:    "idsrv",
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),

			HttpOnly: true,
		}

		http.SetCookie(w, c)

		return
	})

	http.Handle("/", r)

	n := negroni.New()
	n.Use(negroni.NewLogger())
	n.Use(negroni.HandlerFunc(BasicMiddleware))

	n.UseHandler(r)

	http.ListenAndServe(":5002", r)
}

func main() {

	initRoutes()

}
