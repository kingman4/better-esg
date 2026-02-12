package fdaclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Environment controls which FDA API endpoints the client targets.
type Environment string

const (
	EnvProd Environment = "prod"
	EnvTest Environment = "test"
)

// Config holds the configuration for the FDA ESG NextGen API client.
type Config struct {
	ExternalBaseURL string      // e.g. https://external-api-esgng.fda.gov
	UploadBaseURL   string      // e.g. https://upload-api-esgng.fda.gov
	ClientID        string
	ClientSecret    string
	Environment     Environment // prod or test
}

// Client interacts with the FDA ESG NextGen API.
type Client struct {
	config     Config
	httpClient *http.Client

	// Token cache
	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

// tokenResponse maps the FDA OAuth2 token response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// errorResponse maps FDA error responses.
type errorResponse struct {
	ESGNGCode        string `json:"esgngcode"`
	ESGNGDescription string `json:"esgngdescription"`
	Message          string `json:"message"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// New creates a new FDA API client.
func New(cfg Config) *Client {
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetToken returns a valid OAuth2 access token, fetching or refreshing as needed.
// Tokens are cached until 60 seconds before expiry to avoid edge-case failures.
func (c *Client) GetToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (with 60s buffer)
	if c.token != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return c.token, nil
	}

	token, expiresIn, err := c.fetchToken(ctx)
	if err != nil {
		return "", err
	}

	c.token = token
	c.tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return c.token, nil
}

// fetchToken requests a new OAuth2 token from the FDA token endpoint.
func (c *Client) fetchToken(ctx context.Context) (string, int, error) {
	tokenURL := c.config.ExternalBaseURL + "/as/token.oauth2"

	form := url.Values{}
	form.Set("client_id", c.config.ClientID)
	form.Set("client_secret", c.config.ClientSecret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid profile")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp errorResponse
		json.NewDecoder(resp.Body).Decode(&errResp)
		return "", 0, fmt.Errorf("token request returned %d: %s (code: %s)",
			resp.StatusCode, errResp.ESGNGDescription, errResp.ESGNGCode)
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", 0, fmt.Errorf("decoding token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("empty access token in response")
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

// CredentialPath returns the FDA credential submission endpoint path
// based on the configured environment (prod vs test).
func (c *Client) CredentialPath() string {
	if c.config.Environment == EnvProd {
		return "/api/esgng/v1/credentials/api"
	}
	return "/api/esgng/v1/credentials/api/test"
}
