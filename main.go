package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	cognitoidentity "github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

type ClaimsPage struct {
	IDToken     string
	AccessToken string
	Claims      jwt.MapClaims
	S3Objects   []string
}

// --- Environment settings (Change these for your project) ---
var (
	clientID       = "your_client_id" // Replace with your actual client ID
	clientSecret   = "" // Leave empty if your App Client does NOT have a secret
	redirectURL    = "http://localhost:8080/callback"
	issuerURL      = "https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_oGOrYKmfK"
	region         = "ap-northeast-1"
	userPoolID     = "your_user_pool_id" // Replace with your actual user pool ID
	identityPoolID = "your_identity_pool_id" // Replace with your actual identity pool ID
	accountID      = "your_account_id" // Replace with your actual AWS account ID
	bucketName     = "your_bucket_name" // Replace with your actual S3 bucket name
	provider       *oidc.Provider
	oauth2Config   oauth2.Config
)
// -------------------------------------------------------------

func init() {
	ctx := context.Background()

	var err error
	provider, err = oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Fatalf("Failed to initialize OIDC provider: %v", err)
	}

	oauth2Config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret, // Can stay empty if no client secret
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

	fmt.Println("Server is running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
		<html>
		<body>
			<h1>Welcome</h1>
			<a href="/login">Login with Cognito</a>
		</body>
		</html>`)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := "random_state" // You can make this more secure
	url := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code in request", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token found in token response", http.StatusInternalServerError)
		return
	}

	idToken, _, err := new(jwt.Parser).ParseUnverified(rawIDToken, jwt.MapClaims{})
	if err != nil {
		http.Error(w, "Failed to parse ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	claims, ok := idToken.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid ID token claims", http.StatusInternalServerError)
		return
	}

	awsCreds, err := getAWSCredentials(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to get AWS credentials: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s3Objects, err := listS3Objects(ctx, awsCreds)
	if err != nil {
		http.Error(w, "Failed to access S3 bucket: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := ClaimsPage{
		IDToken:     rawIDToken,
		AccessToken: token.AccessToken,
		Claims:      claims,
		S3Objects:   s3Objects,
	}

	tmpl := `
		<html>
		<body>
			<h1>Login Successful</h1>
			<h2>ID Token</h2><p>{{.IDToken}}</p>
			<h2>Access Token</h2><p>{{.AccessToken}}</p>
			<h2>Claims</h2><ul>{{range $key, $value := .Claims}}<li><b>{{$key}}</b>: {{$value}}</li>{{end}}</ul>
			<h2>S3 Objects</h2><ul>{{range .S3Objects}}<li>{{.}}</li>{{end}}</ul>
			<a href="/logout">Logout</a>
		</body>
		</html>`

	t := template.Must(template.New("claims").Parse(tmpl))
	t.Execute(w, data)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusFound)
}

func getAWSCredentials(ctx context.Context, idToken string) (*aws.Credentials, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	identityClient := cognitoidentity.NewFromConfig(cfg)

	getIDResp, err := identityClient.GetId(ctx, &cognitoidentity.GetIdInput{
		AccountId:      aws.String(accountID),
		IdentityPoolId: aws.String(identityPoolID),
		Logins: map[string]string{
			fmt.Sprintf("cognito-idp.%s.amazonaws.com/%s", region, userPoolID): idToken,
		},
	})
	if err != nil {
		return nil, err
	}

	credsResp, err := identityClient.GetCredentialsForIdentity(ctx, &cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: getIDResp.IdentityId,
		Logins: map[string]string{
			fmt.Sprintf("cognito-idp.%s.amazonaws.com/%s", region, userPoolID): idToken,
		},
	})
	if err != nil {
		return nil, err
	}

	return &aws.Credentials{
		AccessKeyID:     *credsResp.Credentials.AccessKeyId,
		SecretAccessKey: *credsResp.Credentials.SecretKey,
		SessionToken:    *credsResp.Credentials.SessionToken,
	}, nil
}

func listS3Objects(ctx context.Context, creds *aws.Credentials) ([]string, error) {
	s3Client := s3.New(s3.Options{
		Region: region,
		Credentials: credentials.NewStaticCredentialsProvider(
			creds.AccessKeyID,
			creds.SecretAccessKey,
			creds.SessionToken,
		),
	})

	resp, err := s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, obj := range resp.Contents {
		keys = append(keys, *obj.Key)
	}
	return keys, nil
}
