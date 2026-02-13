package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	_ "github.com/lib/pq"
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
	case "send":
		runSend(cfg, args)
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
	case "seed-key":
		runSeedKey(args)
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
  send       Submit a file to FDA in one shot (create + submit + upload + finalize)
  status     Check submission status (polls FDA)
  acks       List stored acknowledgements
  list       List submissions

  Advanced (individual pipeline steps):
    create     Create a new submission record
    submit     Initiate FDA workflow for a submission
    upload     Upload a file to a submission
    finalize   Finalize and submit to FDA

  Admin:
    seed-key   Bootstrap org, user, and API key (requires DATABASE_URL)
    version    Print version

Environment:
  ESG_SERVER_URL  Server base URL (default: http://localhost:8080)
  ESG_API_KEY     API key (optional if server has AUTH_DISABLED=true)
  DATABASE_URL    PostgreSQL connection string (required for seed-key)

Examples:
  esg-cli send --file report.xml
  esg-cli list --table
  esg-cli status --id <submission-id>

Run 'esg-cli <command> --help' for command-specific flags.
`)
}

// --- Commands ---

func runSend(cfg config, args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	name := fs.String("name", "", "submission label (defaults to filename)")
	filePath := fs.String("file", "", "path to file (required)")
	subType := fs.String("type", "", "submission type (e.g. NDA, ANDA, IND, BLA)")
	center := fs.String("center", "", "FDA center (e.g. CDER, CBER)")
	protocol := fs.String("protocol", "API", "submission protocol")
	desc := fs.String("desc", "", "description")
	fs.Parse(args)

	if *filePath == "" {
		fatal("--file is required")
	}
	if *name == "" {
		*name = filepath.Base(*filePath)
	}
	if *subType == "" {
		*subType = promptChoice("Select submission type:", submissionTypes)
	}
	if *center == "" {
		*center = promptChoice("Select FDA center:", fdaCenters)
	}

	// Verify the file exists before starting the pipeline.
	fi, err := os.Stat(*filePath)
	if err != nil {
		fatal("cannot access file: %v", err)
	}
	progress("file: %s (%.1f KB)", filepath.Base(*filePath), float64(fi.Size())/1024)

	// Step 1: Create submission
	progress("creating submission...")
	createBody := map[string]any{
		"fda_center":          *center,
		"submission_type":     *subType,
		"submission_name":     *name,
		"submission_protocol": *protocol,
		"file_count":          1,
	}
	if *desc != "" {
		createBody["description"] = *desc
	}
	createResp := mustDo(cfg, "POST", "/api/v1/submissions", jsonBody(createBody))

	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createResp, &created); err != nil {
		fatal("parsing create response: %v", err)
	}
	progress("  submission %s created", truncate(created.ID, 8))

	// Step 2: Initiate FDA workflow (credentials + payload)
	progress("initiating FDA workflow...")
	submitResp := mustDo(cfg, "POST", "/api/v1/submissions/"+created.ID+"/submit", jsonBody(map[string]any{}))

	var submitted struct {
		CoreID    string `json:"core_id"`
		PayloadID string `json:"payload_id"`
	}
	if err := json.Unmarshal(submitResp, &submitted); err != nil {
		fatal("parsing submit response: %v", err)
	}
	progress("  core_id=%s payload_id=%s", submitted.CoreID, submitted.PayloadID)

	// Step 3: Upload file
	progress("uploading %s...", filepath.Base(*filePath))
	f, err := os.Open(*filePath)
	if err != nil {
		fatal("opening file: %v", err)
	}
	defer f.Close()

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

	uploadURL := cfg.serverURL + "/api/v1/submissions/" + created.ID + "/files"
	req, err := http.NewRequest("POST", uploadURL, &buf)
	if err != nil {
		fatal("creating upload request: %v", err)
	}
	if cfg.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{Timeout: 10 * time.Minute}
	httpResp, err := client.Do(req)
	if err != nil {
		fatal("upload failed: %v", err)
	}
	defer httpResp.Body.Close()

	uploadBody, _ := io.ReadAll(httpResp.Body)
	if httpResp.StatusCode >= 400 {
		fatal("upload failed (%d): %s", httpResp.StatusCode, string(uploadBody))
	}
	progress("  upload complete")

	// Step 4: Finalize
	progress("finalizing submission...")
	finalResp := mustDo(cfg, "POST", "/api/v1/submissions/"+created.ID+"/finalize", nil)

	var finalized struct {
		Status        string `json:"status"`
		WorkflowState string `json:"workflow_state"`
	}
	if err := json.Unmarshal(finalResp, &finalized); err != nil {
		fatal("parsing finalize response: %v", err)
	}
	progress("  done — status=%s workflow=%s", finalized.Status, finalized.WorkflowState)
	progress("")
	progress("submission %s submitted to FDA", truncate(created.ID, 8))
	progress("track with: esg-cli status --id %s", created.ID)

	// Print full finalize response as JSON to stdout for scripting
	printJSON(finalResp)
}

func runCreate(cfg config, args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	name := fs.String("name", "", "submission name (required)")
	subType := fs.String("type", "", "submission type (e.g. NDA, ANDA, IND, BLA)")
	center := fs.String("center", "", "FDA center (e.g. CDER, CBER)")
	protocol := fs.String("protocol", "API", "submission protocol")
	fileCount := fs.Int("files", 1, "expected file count")
	desc := fs.String("desc", "", "description")
	fs.Parse(args)

	if *name == "" {
		fatal("--name is required")
	}
	if *subType == "" {
		*subType = promptChoice("Select submission type:", submissionTypes)
	}
	if *center == "" {
		*center = promptChoice("Select FDA center:", fdaCenters)
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
	fs.Parse(args)

	if *id == "" {
		fatal("--id is required")
	}

	resp := mustDo(cfg, "POST", "/api/v1/submissions/"+*id+"/submit", jsonBody(map[string]any{}))
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
	if cfg.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	}
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

func runSeedKey(args []string) {
	fs := flag.NewFlagSet("seed-key", flag.ExitOnError)
	orgName := fs.String("org", "Default", "organization name")
	orgSlug := fs.String("slug", "default", "organization slug (unique)")
	email := fs.String("email", "admin@localhost", "user email")
	keyName := fs.String("name", "default", "API key name")
	role := fs.String("role", "admin", "API key role")
	fs.Parse(args)

	dbURL := buildDatabaseURL()
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fatal("connecting to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		fatal("database not reachable: %v", err)
	}

	ctx := context.Background()

	// Upsert organization
	var orgID string
	err = db.QueryRowContext(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $2)
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, *orgName, *orgSlug).Scan(&orgID)
	if err != nil {
		fatal("creating organization: %v", err)
	}

	// Upsert user
	var userID string
	err = db.QueryRowContext(ctx,
		`INSERT INTO users (org_id, email, role) VALUES ($1, $2, 'admin')
		 ON CONFLICT (org_id, email) DO UPDATE SET role = EXCLUDED.role
		 RETURNING id`, orgID, *email).Scan(&userID)
	if err != nil {
		fatal("creating user: %v", err)
	}

	// Generate API key
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		fatal("generating random key: %v", err)
	}
	rawKey := hex.EncodeToString(rawBytes)
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := rawKey[:8]

	_, err = db.ExecContext(ctx,
		`INSERT INTO api_keys (org_id, user_id, key_hash, key_prefix, name, role)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		orgID, userID, keyHash, keyPrefix, *keyName, *role)
	if err != nil {
		fatal("creating API key: %v", err)
	}

	// Print raw key to stdout (for scripting: KEY=$(esg-cli seed-key))
	fmt.Println(rawKey)
	// Print details to stderr (visible to human, not captured by $())
	fmt.Fprintf(os.Stderr, "\nAPI key created successfully.\n")
	fmt.Fprintf(os.Stderr, "  Prefix: %s\n", keyPrefix)
	fmt.Fprintf(os.Stderr, "  Org:    %s (slug: %s, id: %s)\n", *orgName, *orgSlug, orgID)
	fmt.Fprintf(os.Stderr, "  User:   %s (id: %s)\n", *email, userID)
	fmt.Fprintf(os.Stderr, "\nSave this key — it cannot be retrieved later.\n")
	fmt.Fprintf(os.Stderr, "Add to .env:  ESG_API_KEY=%s\n", rawKey)
}

func buildDatabaseURL() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	host := envOrDefault("DB_HOST", "localhost")
	port := envOrDefault("DB_PORT", "5432")
	user := envOrDefault("DB_USER", "esg")
	pass := envOrDefault("DB_PASSWORD", "esg")
	name := envOrDefault("DB_NAME", "esg")
	sslmode := envOrDefault("DB_SSLMODE", "disable")
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, name, sslmode)
}

// --- HTTP helpers ---

func mustDo(cfg config, method, path string, body io.Reader) []byte {
	url := cfg.serverURL + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		fatal("creating request: %v", err)
	}
	if cfg.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.apiKey)
	}
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

// --- Interactive prompts ---

type choice struct {
	Value string
	Label string
}

var submissionTypes = []choice{
	{"NDA", "New Drug Application"},
	{"ANDA", "Abbreviated New Drug Application (Generic)"},
	{"IND", "Investigational New Drug"},
	{"BLA", "Biologics License Application"},
	{"DMF", "Drug Master File"},
	{"510K", "Premarket Notification (Medical Devices)"},
	{"EUA", "Emergency Use Authorization"},
}

var fdaCenters = []choice{
	{"CDER", "Center for Drug Evaluation and Research"},
	{"CBER", "Center for Biologics Evaluation and Research"},
	{"CDRH", "Center for Devices and Radiological Health"},
	{"CVM", "Center for Veterinary Medicine"},
	{"CTP", "Center for Tobacco Products"},
	{"CFSAN", "Center for Food Safety and Applied Nutrition"},
	{"OC", "Office of the Commissioner"},
}

// promptChoice displays a numbered menu on stderr and reads the user's selection
// from stdin. Returns the chosen value. Exits on invalid input.
func promptChoice(prompt string, choices []choice) string {
	fmt.Fprintf(os.Stderr, "\n%s\n\n", prompt)
	for i, c := range choices {
		fmt.Fprintf(os.Stderr, "  %d) %-6s — %s\n", i+1, c.Value, c.Label)
	}
	fmt.Fprintf(os.Stderr, "\nEnter number (1-%d): ", len(choices))

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		fatal("no input received")
	}
	input := strings.TrimSpace(scanner.Text())
	n, err := strconv.Atoi(input)
	if err != nil || n < 1 || n > len(choices) {
		fatal("invalid selection: %s (expected 1-%d)", input, len(choices))
	}
	selected := choices[n-1]
	fmt.Fprintf(os.Stderr, "  → %s\n", selected.Value)
	return selected.Value
}

// --- Utility ---

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

func progress(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
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
