package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

type ClaimsPage struct {
	IDToken     string
	AccessToken string
	Claims      jwt.MapClaims
}

var (
	// Replace these with your Cognito app client ID and secret
	clientID     = "your_client_id"
	clientSecret = ""
	redirectURL  = "http://localhost:8080/callback"
	// Replace {region} and {user_pool_id} with your AWS Cognito region and user pool ID
	// For example: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456789"
	issuerURL    = "https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"
	provider     *oidc.Provider
	oauth2Config oauth2.Config
)

func init() {
	var err error
	provider, err = oidc.NewProvider(context.Background(), issuerURL)
	if err != nil {
		log.Fatalf("Failed to create OIDC provider: %v", err)
	}

	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID},
	}
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/logout", handleLogout)

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `
		<html>
		<body>
			<h1>Welcome to Cognito OIDC Go App</h1>
			<a href="/login">Login with Cognito</a>
		</body>
		</html>`
	fmt.Fprint(w, html)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := "state"
	url := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code in request", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in token response", http.StatusInternalServerError)
		return
	}

	idToken, _, err := new(jwt.Parser).ParseUnverified(rawIDToken, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "Failed to parse ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	claims, ok := idToken.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid ID Token claims", http.StatusInternalServerError)
		return
	}

	pageData := ClaimsPage{
		IDToken:     rawIDToken,
		AccessToken: token.AccessToken,
		Claims:      claims,
	}

	tmpl := `
		<html>
			<body>
				<h1>Login Successful</h1>
				<h2>ID Token:</h2>
				<p>{{.IDToken}}</p>
				<h2>Access Token:</h2>
				<p>{{.AccessToken}}</p>
				<h2>Claims:</h2>
				<ul>
					{{range $key, $value := .Claims}}
						<li><strong>{{$key}}:</strong> {{$value}}</li>
					{{end}}
				</ul>
				<a href="/logout">Logout</a>
			</body>
		</html>`

	t := template.Must(template.New("claims").Parse(tmpl))
	t.Execute(w, pageData)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}
