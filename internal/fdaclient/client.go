package fdaclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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

// CredentialRequest is the JSON body sent to the FDA credential submission endpoint.
type CredentialRequest struct {
	UserID             string `json:"user_id"`
	FDACenter          string `json:"fda_center"`
	CompanyID          string `json:"company_id"`
	SubmissionType     string `json:"submission_type"`
	SubmissionProtocol string `json:"submission_protocol"`
	FileCount          int    `json:"file_count"`
	Description        string `json:"description,omitempty"`
}

// CredentialResponse is the JSON response from the FDA credential submission endpoint.
type CredentialResponse struct {
	CoreID           string `json:"core_id"`
	TempUser         string `json:"temp_user"`
	TempPassword     string `json:"temp_password"`
	ESGNGCode        string `json:"esgngcode"`
	ESGNGDescription string `json:"esgngdescription"`
}

// PayloadResponse is the JSON response from the FDA file payload endpoint.
type PayloadResponse struct {
	PayloadID string       `json:"payloadId"`
	Links     PayloadLinks `json:"links"`
}

// PayloadLinks contains the upload and submit URLs returned by the payload endpoint.
type PayloadLinks struct {
	UploadLink string `json:"uploadLink"`
	SubmitLink string `json:"submitLink"`
}

// UploadResponse is the JSON response from the FDA file upload endpoint.
type UploadResponse struct {
	FileName         string `json:"fileName"`
	FileSize         int64  `json:"fileSize"`
	ESGNGCode        string `json:"esgngcode"`
	ESGNGDescription string `json:"esgngdescription"`
}

// SubmitRequest is the JSON body sent to the FDA file submit endpoint.
// Uses temp credentials from the credential step — no Bearer token.
type SubmitRequest struct {
	TempUser       string `json:"temp_user"`
	TempPassword   string `json:"temp_password"`
	SHA256Checksum string `json:"sha256_checksum"`
}

// SubmitResponse is the JSON response from the FDA file submit endpoint.
type SubmitResponse struct {
	CoreID           string `json:"core_id"`
	ESGNGCode        string `json:"esgngcode"`
	ESGNGDescription string `json:"esgngdescription"`
}

// SubmissionStatusResponse is the JSON response from the submission status endpoint.
type SubmissionStatusResponse struct {
	CoreID           string               `json:"core_id"`
	Status           string               `json:"status"`
	ESGNGCode        string               `json:"esgngcode"`
	ESGNGDescription string               `json:"esgngdescription"`
	Acknowledgements []AcknowledgementRef `json:"acknowledgements"`
}

// AcknowledgementRef is a reference to an acknowledgement returned in the status response.
type AcknowledgementRef struct {
	AcknowledgementID string `json:"acknowledgement_id"`
	Type              string `json:"type"`
}

// AcknowledgementResponse is the JSON response from the acknowledgement endpoint.
type AcknowledgementResponse struct {
	AcknowledgementID string         `json:"acknowledgement_id"`
	Type              string         `json:"type"`
	RawMessage        string         `json:"raw_message"`
	ParsedData        map[string]any `json:"parsed_data"`
	ESGNGCode         string         `json:"esgngcode"`
	ESGNGDescription  string         `json:"esgngdescription"`
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
// Retries transient failures with exponential backoff (1s, 2s, 4s, 8s).
func (c *Client) fetchToken(ctx context.Context) (string, int, error) {
	tokenURL := c.config.ExternalBaseURL + "/as/token.oauth2"

	form := url.Values{}
	form.Set("client_id", c.config.ClientID)
	form.Set("client_secret", c.config.ClientSecret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "openid profile")
	formBody := form.Encode()

	var token string
	var expiresIn int

	err := retryDo(ctx, retryToken, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(formBody))
		if err != nil {
			return &permanentError{err: fmt.Errorf("creating token request: %w", err)}
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("token request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp errorResponse
			json.NewDecoder(resp.Body).Decode(&errResp)
			fdaErr := fmt.Errorf("token request returned %d: %s (code: %s)",
				resp.StatusCode, errResp.ESGNGDescription, errResp.ESGNGCode)
			if isRetryable(resp.StatusCode) {
				return &retryableError{err: fdaErr}
			}
			return &permanentError{err: fdaErr}
		}

		var tokenResp tokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return &permanentError{err: fmt.Errorf("decoding token response: %w", err)}
		}

		if tokenResp.AccessToken == "" {
			return &permanentError{err: fmt.Errorf("empty access token in response")}
		}

		token = tokenResp.AccessToken
		expiresIn = tokenResp.ExpiresIn
		return nil
	})

	return token, expiresIn, err
}

// CredentialPath returns the FDA credential submission endpoint path
// based on the configured environment (prod vs test).
func (c *Client) CredentialPath() string {
	if c.config.Environment == EnvProd {
		return "/api/esgng/v1/credentials/api"
	}
	return "/api/esgng/v1/credentials/api/test"
}

// SubmitCredentials sends a credential submission request to the FDA API.
// It acquires a Bearer token automatically, then POSTs the credential request.
// Returns the temporary credentials (core_id, temp_user, temp_password) needed
// for subsequent file upload and submission steps.
// Retries transient failures with exponential backoff (2s, 4s, 8s).
func (c *Client) SubmitCredentials(ctx context.Context, cred CredentialRequest) (*CredentialResponse, error) {
	token, err := c.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquiring token for credential submission: %w", err)
	}

	bodyBytes, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("marshalling credential request: %w", err)
	}

	credURL := c.config.ExternalBaseURL + c.CredentialPath()

	var result CredentialResponse
	err = retryDo(ctx, retryDefault, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, credURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return &permanentError{err: fmt.Errorf("creating credential request: %w", err)}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("credential request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp errorResponse
			json.NewDecoder(resp.Body).Decode(&errResp)
			fdaErr := fmt.Errorf("credential request returned %d: %s (code: %s)",
				resp.StatusCode, errResp.ESGNGDescription, errResp.ESGNGCode)
			if isRetryable(resp.StatusCode) {
				return &retryableError{err: fdaErr}
			}
			return &permanentError{err: fdaErr}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return &permanentError{err: fmt.Errorf("decoding credential response: %w", err)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPayload requests a new payload ID from the FDA upload API.
// This endpoint requires NO authentication.
// Returns the payload ID and links for subsequent file upload and submission.
// Retries transient failures with exponential backoff (2s, 4s, 8s).
func (c *Client) GetPayload(ctx context.Context) (*PayloadResponse, error) {
	payloadURL := c.config.UploadBaseURL + "/rest/forms/v1/fileupload/payload"

	var result PayloadResponse
	err := retryDo(ctx, retryDefault, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, payloadURL, nil)
		if err != nil {
			return &permanentError{err: fmt.Errorf("creating payload request: %w", err)}
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("payload request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp errorResponse
			json.NewDecoder(resp.Body).Decode(&errResp)
			fdaErr := fmt.Errorf("payload request returned %d: %s (code: %s)",
				resp.StatusCode, errResp.ESGNGDescription, errResp.ESGNGCode)
			if isRetryable(resp.StatusCode) {
				return &retryableError{err: fdaErr}
			}
			return &permanentError{err: fdaErr}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return &permanentError{err: fmt.Errorf("decoding payload response: %w", err)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// UploadFile uploads a single file to an existing payload via the FDA upload API.
// Requires a Bearer token. The file is sent as multipart/form-data.
// Retries transient failures with linear backoff (5s, 10s, 15s, 20s, 25s).
func (c *Client) UploadFile(ctx context.Context, payloadID, fileName string, file io.Reader) (*UploadResponse, error) {
	token, err := c.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquiring token for file upload: %w", err)
	}

	// Build multipart body once — held in memory for retries
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return nil, fmt.Errorf("creating multipart form file: %w", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, fmt.Errorf("writing file to multipart: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing multipart writer: %w", err)
	}

	bodyBytes := buf.Bytes()
	contentType := writer.FormDataContentType()
	uploadURL := c.config.UploadBaseURL + "/rest/forms/v1/fileupload/payload/" + payloadID + "/file"

	var result UploadResponse
	err = retryDo(ctx, retryUpload, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return &permanentError{err: fmt.Errorf("creating upload request: %w", err)}
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("upload request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp errorResponse
			json.NewDecoder(resp.Body).Decode(&errResp)
			fdaErr := fmt.Errorf("upload request returned %d: %s (code: %s)",
				resp.StatusCode, errResp.ESGNGDescription, errResp.ESGNGCode)
			if isRetryable(resp.StatusCode) {
				return &retryableError{err: fdaErr}
			}
			return &permanentError{err: fdaErr}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return &permanentError{err: fmt.Errorf("decoding upload response: %w", err)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// SubmitPayload finalizes a file submission to the FDA.
// This endpoint does NOT use a Bearer token. Instead, it authenticates via
// temp_user and temp_password (from the credential step) in the JSON body,
// along with the sha256_checksum of the uploaded file(s).
// Retries transient failures with exponential backoff (2s, 4s, 8s).
func (c *Client) SubmitPayload(ctx context.Context, payloadID string, submit SubmitRequest) (*SubmitResponse, error) {
	bodyBytes, err := json.Marshal(submit)
	if err != nil {
		return nil, fmt.Errorf("marshalling submit request: %w", err)
	}

	submitURL := c.config.UploadBaseURL + "/rest/forms/v1/fileupload/payload/" + payloadID + "/submit"

	var result SubmitResponse
	err = retryDo(ctx, retryDefault, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return &permanentError{err: fmt.Errorf("creating submit request: %w", err)}
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("submit request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp errorResponse
			json.NewDecoder(resp.Body).Decode(&errResp)
			fdaErr := fmt.Errorf("submit request returned %d: %s (code: %s)",
				resp.StatusCode, errResp.ESGNGDescription, errResp.ESGNGCode)
			if isRetryable(resp.StatusCode) {
				return &retryableError{err: fdaErr}
			}
			return &permanentError{err: fdaErr}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return &permanentError{err: fmt.Errorf("decoding submit response: %w", err)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetSubmissionStatus retrieves the current status of a submission by core_id.
// Requires a Bearer token. Returns the status and any available acknowledgement references.
// Retries transient failures with exponential backoff (2s, 4s, 8s).
func (c *Client) GetSubmissionStatus(ctx context.Context, coreID string) (*SubmissionStatusResponse, error) {
	token, err := c.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquiring token for status check: %w", err)
	}

	statusURL := c.config.ExternalBaseURL + "/api/esgng/v1/submissions/" + coreID

	var result SubmissionStatusResponse
	err = retryDo(ctx, retryDefault, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
		if err != nil {
			return &permanentError{err: fmt.Errorf("creating status request: %w", err)}
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("status request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp errorResponse
			json.NewDecoder(resp.Body).Decode(&errResp)
			fdaErr := fmt.Errorf("status request returned %d: %s (code: %s)",
				resp.StatusCode, errResp.ESGNGDescription, errResp.ESGNGCode)
			if isRetryable(resp.StatusCode) {
				return &retryableError{err: fdaErr}
			}
			return &permanentError{err: fdaErr}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return &permanentError{err: fmt.Errorf("decoding status response: %w", err)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetAcknowledgement retrieves a specific acknowledgement by ID.
// Requires a Bearer token. Returns the acknowledgement details including raw message and parsed data.
// Retries transient failures with exponential backoff (2s, 4s, 8s).
func (c *Client) GetAcknowledgement(ctx context.Context, acknowledgementID string) (*AcknowledgementResponse, error) {
	token, err := c.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquiring token for acknowledgement: %w", err)
	}

	ackURL := c.config.ExternalBaseURL + "/api/esgng/v1/acknowledgements/" + acknowledgementID

	var result AcknowledgementResponse
	err = retryDo(ctx, retryDefault, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ackURL, nil)
		if err != nil {
			return &permanentError{err: fmt.Errorf("creating acknowledgement request: %w", err)}
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("acknowledgement request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			var errResp errorResponse
			json.NewDecoder(resp.Body).Decode(&errResp)
			fdaErr := fmt.Errorf("acknowledgement request returned %d: %s (code: %s)",
				resp.StatusCode, errResp.ESGNGDescription, errResp.ESGNGCode)
			if isRetryable(resp.StatusCode) {
				return &retryableError{err: fdaErr}
			}
			return &permanentError{err: fdaErr}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return &permanentError{err: fmt.Errorf("decoding acknowledgement response: %w", err)}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}
