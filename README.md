# login-app

This is a simple application to test login using Amazon Cognito Hosted UI and OpenID Connect (OIDC) in Go.

## How to Run

1. Install Go if you haven't already.

2. Clone this repository.

3. Run the application:

```bash
go run main.go
```

4. Open your browser and access:

```
http://localhost:8080
```

5. Click "Login with Cognito" to start the login flow.

After successful login, the user information (claims) will be displayed.

## Notes

- Make sure your Cognito User Pool and App Client are correctly configured.
- Ensure the callback URL (`http://localhost:8080/callback`) and logout URL (`http://localhost:8080/`) are properly set in your Cognito App Client settings.
- The `issuerURL` in the code should match your **Cognito Hosted Domain**, like:
For example:

```go
	// Replace {region} and {user_pool_id} with your AWS Cognito region and user pool ID
	// For example: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_123456789"
```
