package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

const version = "0.1.0"

// config holds CLI-wide settings derived from env vars and flags.
type config struct {
	serverURL string
	apiKey    string
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cfg := config{
		serverURL: envOrDefault("ESG_SERVER_URL", "http://localhost:8080"),
		apiKey:    os.Getenv("ESG_API_KEY"),
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "create":
		runCreate(cfg, args)
	case "list":
		runList(cfg, args)
	case "submit":
		runSubmit(cfg, args)
	case "upload":
		runUpload(cfg, args)
	case "finalize":
		runFinalize(cfg, args)
	case "status":
		runStatus(cfg, args)
	case "acks":
		runAcks(cfg, args)
	case "version":
		fmt.Printf("esg-cli %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `esg-cli — FDA ESG NextGen submission client

Usage:
  esg-cli <command> [flags]

Commands:
  create     Create a new submission
  list       List submissions
  submit     Initiate FDA workflow for a submission
  upload     Upload a file to a submission
  finalize   Finalize and submit to FDA
  status     Check submission status (polls FDA)
  acks       List stored acknowledgements
  version    Print version

Environment:
  ESG_SERVER_URL  Server base URL (default: http://localhost:8080)
  ESG_API_KEY     API key (required)

Run 'esg-cli <command> --help' for command-specific flags.
`)
}

// --- Commands ---

func runCreate(cfg config, args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	name := fs.String("name", "", "submission name (required)")
	subType := fs.String("type", "ANDA", "submission type")
	center := fs.String("center", "CDER", "FDA center")
	protocol := fs.String("protocol", "API", "submission protocol")
	fileCount := fs.Int("files", 1, "expected file count")
	desc := fs.String("desc", "", "description")
	fs.Parse(args)

	if *name == "" {
		fatal("--name is required")
	}

	body := map[string]any{
		"fda_center":          *center,
		"submission_type":     *subType,
		"submission_name":     *name,
		"submission_protocol": *protocol,
		"file_count":          *fileCount,
	}
	if *desc != "" {
		body["description"] = *desc
	}

	resp := mustDo(cfg, "POST", "/api/v1/submissions", jsonBody(body))
	printJSON(resp)
}

func runList(cfg config, args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	limit := fs.Int("limit", 20, "max results")
	offset := fs.Int("offset", 0, "offset")
	table := fs.Bool("table", false, "print as table instead of JSON")
	fs.Parse(args)

	path := fmt.Sprintf("/api/v1/submissions?limit=%d&offset=%d", *limit, *offset)
	resp := mustDo(cfg, "GET", path, nil)

	if *table {
		printSubmissionsTable(resp)
		return
	}
	printJSON(resp)
}

func runSubmit(cfg config, args []string) {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	id := fs.String("id", "", "submission ID (required)")
	email := fs.String("email", "", "user email (required)")
	company := fs.String("company", "", "company ID (required)")
	fs.Parse(args)

	if *id == "" || *email == "" || *company == "" {
		fatal("--id, --email, and --company are required")
	}

	body := map[string]any{
		"user_email": *email,
		"company_id": *company,
	}

	resp := mustDo(cfg, "POST", "/api/v1/submissions/"+*id+"/submit", jsonBody(body))
	printJSON(resp)
}

func runUpload(cfg config, args []string) {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	id := fs.String("id", "", "submission ID (required)")
	filePath := fs.String("file", "", "path to file (required)")
	fs.Parse(args)

	if *id == "" || *filePath == "" {
		fatal("--id and --file are required")
	}

	f, err := os.Open(*filePath)
	if err != nil {
		fatal("opening file: %v", err)
	}
	defer f.Close()

	// Build multipart request
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", filepath.Base(*filePath))
	if err != nil {
		fatal("creating form file: %v", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		fatal("copying file: %v", err)
	}
	writer.Close()

	url := cfg.serverURL + "/api/v1/submissions/" + *id + "/files"
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		fatal("creating request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 10 * time.Minute}
	httpResp, err := client.Do(req)
	if err != nil {
		fatal("upload failed: %v", err)
	}
	defer httpResp.Body.Close()

	respBody, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode >= 400 {
		fatal("upload failed (%d): %s", httpResp.StatusCode, string(respBody))
	}
	printRawJSON(respBody)
}

func runFinalize(cfg config, args []string) {
	fs := flag.NewFlagSet("finalize", flag.ExitOnError)
	id := fs.String("id", "", "submission ID (required)")
	fs.Parse(args)

	if *id == "" {
		fatal("--id is required")
	}

	resp := mustDo(cfg, "POST", "/api/v1/submissions/"+*id+"/finalize", nil)
	printJSON(resp)
}

func runStatus(cfg config, args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	id := fs.String("id", "", "submission ID (required)")
	fs.Parse(args)

	if *id == "" {
		fatal("--id is required")
	}

	resp := mustDo(cfg, "GET", "/api/v1/submissions/"+*id+"/status", nil)
	printJSON(resp)
}

func runAcks(cfg config, args []string) {
	fs := flag.NewFlagSet("acks", flag.ExitOnError)
	id := fs.String("id", "", "submission ID (required)")
	fs.Parse(args)

	if *id == "" {
		fatal("--id is required")
	}

	resp := mustDo(cfg, "GET", "/api/v1/submissions/"+*id+"/acknowledgements", nil)
	printJSON(resp)
}

// --- HTTP helpers ---

func mustDo(cfg config, method, path string, body io.Reader) []byte {
	requireAPIKey(cfg)

	url := cfg.serverURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		fatal("creating request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fatal("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		// Try to extract error message from JSON
		var errResp map[string]string
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"]; ok {
				fatal("%s %s → %d: %s", method, path, resp.StatusCode, msg)
			}
		}
		fatal("%s %s → %d: %s", method, path, resp.StatusCode, string(respBody))
	}

	return respBody
}

func jsonBody(v any) io.Reader {
	b, err := json.Marshal(v)
	if err != nil {
		fatal("marshaling JSON: %v", err)
	}
	return bytes.NewReader(b)
}

// --- Output helpers ---

func printJSON(data []byte) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		// Not valid JSON — print raw
		os.Stdout.Write(data)
		return
	}
	buf.WriteByte('\n')
	os.Stdout.Write(buf.Bytes())
}

func printRawJSON(data []byte) {
	printJSON(data)
}

func printSubmissionsTable(data []byte) {
	var subs []map[string]any
	if err := json.Unmarshal(data, &subs); err != nil {
		printJSON(data)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSTATUS\tWORKFLOW\tFILES\tCREATED")
	for _, s := range subs {
		id := truncate(str(s["id"]), 8)
		name := truncate(str(s["submission_name"]), 30)
		status := str(s["status"])
		workflow := str(s["workflow_state"])
		files := str(s["file_count"])
		created := str(s["created_at"])
		if len(created) > 10 {
			created = created[:10]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", id, name, status, workflow, files, created)
	}
	w.Flush()
}

// --- Utility ---

func requireAPIKey(cfg config) {
	if cfg.apiKey == "" {
		fatal("ESG_API_KEY environment variable is required")
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func str(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int(val)) {
			return fmt.Sprintf("%d", int(val))
		}
		return fmt.Sprintf("%.2f", val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + strings.Repeat(".", 3)
}
