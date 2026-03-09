package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- Pure function tests ---

func TestEnvOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		envVal   string
		fallback string
		want     string
	}{
		{"uses env when set", "TEST_ENV_VAR_1", "from-env", "default", "from-env"},
		{"uses fallback when unset", "TEST_ENV_VAR_UNSET_XYZ", "", "default", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVal != "" {
				t.Setenv(tt.key, tt.envVal)
			}
			got := envOrDefault(tt.key, tt.fallback)
			if got != tt.want {
				t.Errorf("envOrDefault(%q, %q) = %q, want %q", tt.key, tt.fallback, got, tt.want)
			}
		})
	}
}

func TestStr(t *testing.T) {
	tests := []struct {
		input any
		want  string
	}{
		{nil, ""},
		{"hello", "hello"},
		{float64(42), "42"},
		{float64(3.14), "3.14"},
		{float64(100), "100"},
		{true, "true"},
		{float64(0), "0"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.input), func(t *testing.T) {
			got := str(tt.input)
			if got != tt.want {
				t.Errorf("str(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long string", 10, "this is..."},
		{"abc", 3, "abc"},
		{"abcdef", 5, "ab..."},
		{"", 5, ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q/%d", tt.input, tt.maxLen), func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestBuildDatabaseURL(t *testing.T) {
	t.Run("uses DATABASE_URL when set", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://custom:pass@host:1234/mydb")
		got := buildDatabaseURL()
		if got != "postgres://custom:pass@host:1234/mydb" {
			t.Errorf("got %q, want DATABASE_URL value", got)
		}
	})

	t.Run("builds from components when DATABASE_URL unset", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")
		t.Setenv("DB_HOST", "myhost")
		t.Setenv("DB_PORT", "9999")
		t.Setenv("DB_USER", "myuser")
		t.Setenv("DB_PASSWORD", "mypass")
		t.Setenv("DB_NAME", "mydb")
		t.Setenv("DB_SSLMODE", "require")

		got := buildDatabaseURL()
		want := "postgres://myuser:mypass@myhost:9999/mydb?sslmode=require"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("uses defaults for missing components", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")
		t.Setenv("DB_HOST", "")
		t.Setenv("DB_PORT", "")
		t.Setenv("DB_USER", "")
		t.Setenv("DB_PASSWORD", "")
		t.Setenv("DB_NAME", "")
		t.Setenv("DB_SSLMODE", "")

		got := buildDatabaseURL()
		want := "postgres://esg:esg@localhost:5432/esg?sslmode=disable"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestJsonBody(t *testing.T) {
	body := jsonBody(map[string]any{"key": "value", "num": 42})
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	if parsed["key"] != "value" {
		t.Errorf("key = %v, want 'value'", parsed["key"])
	}
	if parsed["num"] != float64(42) {
		t.Errorf("num = %v, want 42", parsed["num"])
	}
}

func TestPrintJSON(t *testing.T) {
	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printJSON([]byte(`{"hello":"world","num":1}`))

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, `"hello": "world"`) {
		t.Errorf("expected pretty-printed JSON, got: %s", output)
	}
}

func TestPrintJSON_InvalidJSON(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printJSON([]byte(`not json`))

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if output != "not json" {
		t.Errorf("expected raw passthrough, got: %q", output)
	}
}

func TestPrintSubmissionsTable(t *testing.T) {
	subs := []map[string]any{
		{
			"id":              "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"submission_name": "Test Sub",
			"status":          "submitted",
			"workflow_state":  "SUBMITTED",
			"file_count":      float64(3),
			"created_at":      "2026-02-20T12:00:00Z",
		},
	}
	data, _ := json.Marshal(subs)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printSubmissionsTable(data)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Header
	if !strings.Contains(output, "ID") || !strings.Contains(output, "NAME") {
		t.Errorf("expected table header, got: %s", output)
	}
	// Truncated ID
	if !strings.Contains(output, "aaaaa...") {
		t.Errorf("expected truncated ID, got: %s", output)
	}
	// Data
	if !strings.Contains(output, "Test Sub") {
		t.Errorf("expected submission name, got: %s", output)
	}
	if !strings.Contains(output, "SUBMITTED") {
		t.Errorf("expected workflow state, got: %s", output)
	}
	// Date truncated to 10 chars
	if !strings.Contains(output, "2026-02-20") {
		t.Errorf("expected truncated date, got: %s", output)
	}
}

func TestPrintSubmissionsTable_InvalidJSON(t *testing.T) {
	// Should fall back to printJSON (raw output)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printSubmissionsTable([]byte(`not json`))

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if output != "not json" {
		t.Errorf("expected raw passthrough, got: %q", output)
	}
}

// --- HTTP command tests using httptest ---

// newMockAPI creates a test server that records requests and returns canned responses.
// handler receives the request and returns (statusCode, responseBody).
func newMockAPI(t *testing.T, handler func(r *http.Request) (int, any)) (*httptest.Server, config) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code, body := handler(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(ts.Close)
	return ts, config{serverURL: ts.URL, apiKey: "test-key-123"}
}

func TestMustDo_Success(t *testing.T) {
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		return 200, map[string]string{"status": "ok"}
	})

	resp := mustDo(cfg, "GET", "/test", nil)

	var parsed map[string]string
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if parsed["status"] != "ok" {
		t.Errorf("status = %q, want 'ok'", parsed["status"])
	}
}

func TestMustDo_SetsAuthHeader(t *testing.T) {
	var gotAuth string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotAuth = r.Header.Get("Authorization")
		return 200, map[string]string{}
	})

	mustDo(cfg, "GET", "/test", nil)

	if gotAuth != "Bearer test-key-123" {
		t.Errorf("Authorization = %q, want 'Bearer test-key-123'", gotAuth)
	}
}

func TestMustDo_NoAuthWhenKeyEmpty(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer ts.Close()

	cfg := config{serverURL: ts.URL, apiKey: ""}
	mustDo(cfg, "GET", "/test", nil)

	if gotAuth != "" {
		t.Errorf("Authorization should be empty when apiKey is empty, got %q", gotAuth)
	}
}

func TestMustDo_SetsContentTypeForBody(t *testing.T) {
	var gotCT string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotCT = r.Header.Get("Content-Type")
		return 200, map[string]string{}
	})

	mustDo(cfg, "POST", "/test", jsonBody(map[string]string{"x": "y"}))

	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want 'application/json'", gotCT)
	}
}

func TestMustDo_NoContentTypeForNilBody(t *testing.T) {
	var gotCT string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotCT = r.Header.Get("Content-Type")
		return 200, map[string]string{}
	})

	mustDo(cfg, "GET", "/test", nil)

	if gotCT == "application/json" {
		t.Error("Content-Type should not be set for nil body")
	}
}

func TestMustDo_FatalOnHTTPError(t *testing.T) {
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		return 404, map[string]string{"error": "not found"}
	})

	var exitCode int
	exitFunc = func(code int) { exitCode = code; panic("exit") }
	defer func() { exitFunc = os.Exit }()

	defer func() {
		r := recover()
		if r != "exit" {
			t.Fatal("expected fatal to panic with 'exit'")
		}
		if exitCode != 1 {
			t.Errorf("exit code = %d, want 1", exitCode)
		}
	}()

	mustDo(cfg, "GET", "/missing", nil)
}

func TestMustDo_CorrectMethodAndPath(t *testing.T) {
	var gotMethod, gotPath string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		return 200, map[string]string{}
	})

	mustDo(cfg, "POST", "/api/v1/submissions", jsonBody(map[string]string{}))

	if gotMethod != "POST" {
		t.Errorf("method = %q, want 'POST'", gotMethod)
	}
	if gotPath != "/api/v1/submissions" {
		t.Errorf("path = %q, want '/api/v1/submissions'", gotPath)
	}
}

// --- Command-level tests ---

func TestRunList_JSON(t *testing.T) {
	subs := []map[string]any{
		{"id": "sub-1", "submission_name": "Test", "status": "draft"},
	}

	var gotPath string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotPath = r.URL.RequestURI()
		return 200, subs
	})

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runList(cfg, []string{})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if gotPath != "/api/v1/submissions?limit=20&offset=0" {
		t.Errorf("path = %q, want default limit/offset", gotPath)
	}
	if !strings.Contains(output, "sub-1") {
		t.Errorf("expected submission ID in output, got: %s", output)
	}
}

func TestRunList_Table(t *testing.T) {
	subs := []map[string]any{
		{"id": "aaaaaaaa-1111", "submission_name": "Drug App", "status": "submitted",
			"workflow_state": "SUBMITTED", "file_count": float64(2), "created_at": "2026-02-20T00:00:00Z"},
	}

	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		return 200, subs
	})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runList(cfg, []string{"--table"})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "ID") || !strings.Contains(output, "NAME") {
		t.Errorf("expected table header, got: %s", output)
	}
	if !strings.Contains(output, "Drug App") {
		t.Errorf("expected submission name in table, got: %s", output)
	}
}

func TestRunList_CustomPagination(t *testing.T) {
	var gotPath string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotPath = r.URL.RequestURI()
		return 200, []map[string]any{}
	})

	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	runList(cfg, []string{"--limit", "5", "--offset", "10"})

	w.Close()
	os.Stdout = old

	if gotPath != "/api/v1/submissions?limit=5&offset=10" {
		t.Errorf("path = %q, want custom limit/offset", gotPath)
	}
}

func TestRunStatus(t *testing.T) {
	var gotPath string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotPath = r.URL.Path
		return 200, map[string]string{
			"submission_id":  "abc-123",
			"fda_status":     "PROCESSING",
			"workflow_state": "PROCESSING",
		}
	})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runStatus(cfg, []string{"--id", "abc-123"})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if gotPath != "/api/v1/submissions/abc-123/status" {
		t.Errorf("path = %q, want '/api/v1/submissions/abc-123/status'", gotPath)
	}
	if !strings.Contains(buf.String(), "PROCESSING") {
		t.Errorf("expected PROCESSING in output, got: %s", buf.String())
	}
}

func TestRunStatus_MissingID(t *testing.T) {
	cfg := config{serverURL: "http://unused"}

	var exitCode int
	exitFunc = func(code int) { exitCode = code; panic("exit") }
	defer func() { exitFunc = os.Exit }()

	defer func() {
		r := recover()
		if r != "exit" {
			t.Fatal("expected fatal")
		}
		if exitCode != 1 {
			t.Errorf("exit code = %d, want 1", exitCode)
		}
	}()

	runStatus(cfg, []string{})
}

func TestRunAcks(t *testing.T) {
	var gotPath string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotPath = r.URL.Path
		return 200, []map[string]string{
			{"acknowledgement_id": "ack-1", "type": "Technical"},
		}
	})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runAcks(cfg, []string{"--id", "sub-999"})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if gotPath != "/api/v1/submissions/sub-999/acknowledgements" {
		t.Errorf("path = %q, want '/api/v1/submissions/sub-999/acknowledgements'", gotPath)
	}
	if !strings.Contains(buf.String(), "ack-1") {
		t.Errorf("expected ack-1 in output, got: %s", buf.String())
	}
}

func TestRunSubmit(t *testing.T) {
	var gotPath, gotMethod string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		return 200, map[string]string{"core_id": "CORE-1", "payload_id": "PL-1"}
	})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runSubmit(cfg, []string{"--id", "sub-abc"})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/submissions/sub-abc/submit" {
		t.Errorf("path = %q, want submit endpoint", gotPath)
	}
	if !strings.Contains(buf.String(), "CORE-1") {
		t.Errorf("expected CORE-1 in output, got: %s", buf.String())
	}
}

func TestRunFinalize(t *testing.T) {
	var gotPath string
	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotPath = r.URL.Path
		return 200, map[string]string{"status": "submitted", "workflow_state": "SUBMITTED"}
	})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runFinalize(cfg, []string{"--id", "sub-fin"})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if gotPath != "/api/v1/submissions/sub-fin/finalize" {
		t.Errorf("path = %q, want finalize endpoint", gotPath)
	}
	if !strings.Contains(buf.String(), "SUBMITTED") {
		t.Errorf("expected SUBMITTED in output, got: %s", buf.String())
	}
}

func TestRunCreate(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody map[string]any

	_, cfg := newMockAPI(t, func(r *http.Request) (int, any) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		json.NewDecoder(r.Body).Decode(&gotBody)
		return 201, map[string]string{"id": "new-sub-id"}
	})

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runCreate(cfg, []string{
		"--name", "My Drug App",
		"--type", "NDA",
		"--center", "CDER",
		"--protocol", "API",
		"--files", "3",
		"--desc", "Test submission",
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/submissions" {
		t.Errorf("path = %q, want '/api/v1/submissions'", gotPath)
	}
	if gotBody["submission_name"] != "My Drug App" {
		t.Errorf("submission_name = %v, want 'My Drug App'", gotBody["submission_name"])
	}
	if gotBody["submission_type"] != "NDA" {
		t.Errorf("submission_type = %v, want 'NDA'", gotBody["submission_type"])
	}
	if gotBody["fda_center"] != "CDER" {
		t.Errorf("fda_center = %v, want 'CDER'", gotBody["fda_center"])
	}
	if gotBody["file_count"] != float64(3) {
		t.Errorf("file_count = %v, want 3", gotBody["file_count"])
	}
	if gotBody["description"] != "Test submission" {
		t.Errorf("description = %v, want 'Test submission'", gotBody["description"])
	}
	if !strings.Contains(buf.String(), "new-sub-id") {
		t.Errorf("expected new-sub-id in output, got: %s", buf.String())
	}
}

func TestRunCreate_MissingName(t *testing.T) {
	cfg := config{serverURL: "http://unused"}

	var exitCode int
	exitFunc = func(code int) { exitCode = code; panic("exit") }
	defer func() { exitFunc = os.Exit }()

	defer func() {
		r := recover()
		if r != "exit" {
			t.Fatal("expected fatal")
		}
		if exitCode != 1 {
			t.Errorf("exit code = %d, want 1", exitCode)
		}
	}()

	runCreate(cfg, []string{"--type", "NDA", "--center", "CDER"})
}

func TestRunUpload(t *testing.T) {
	var gotPath, gotCT string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"file_id": "f-1"})
	}))
	defer ts.Close()

	cfg := config{serverURL: ts.URL, apiKey: "key"}

	// Create a temp file to upload
	tmp, err := os.CreateTemp(t.TempDir(), "upload-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	tmp.WriteString("test file content")
	tmp.Close()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runUpload(cfg, []string{"--id", "sub-up", "--file", tmp.Name()})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if gotPath != "/api/v1/submissions/sub-up/files" {
		t.Errorf("path = %q, want upload endpoint", gotPath)
	}
	if !strings.Contains(gotCT, "multipart/form-data") {
		t.Errorf("Content-Type = %q, want multipart/form-data", gotCT)
	}
	if !strings.Contains(buf.String(), "f-1") {
		t.Errorf("expected file_id in output, got: %s", buf.String())
	}
}

func TestRunUpload_MissingFlags(t *testing.T) {
	cfg := config{serverURL: "http://unused"}

	var exitCode int
	exitFunc = func(code int) { exitCode = code; panic("exit") }
	defer func() { exitFunc = os.Exit }()

	defer func() {
		r := recover()
		if r != "exit" {
			t.Fatal("expected fatal")
		}
		if exitCode != 1 {
			t.Errorf("exit code = %d, want 1", exitCode)
		}
	}()

	runUpload(cfg, []string{"--id", "sub-up"}) // missing --file
}
