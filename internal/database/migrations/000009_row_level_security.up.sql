-- Row-Level Security policies for multi-tenant data isolation.
-- These enforce that queries can only access rows belonging to
-- the organization set in app.current_org_id session variable.

ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE submission_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Submissions: isolate by org_id
CREATE POLICY submissions_org_isolation ON submissions
  USING (org_id = current_setting('app.current_org_id')::uuid);

-- Submission files: isolate via submission's org_id
CREATE POLICY submission_files_org_isolation ON submission_files
  USING (submission_id IN (
    SELECT id FROM submissions
    WHERE org_id = current_setting('app.current_org_id')::uuid
  ));

-- Audit logs: isolate by org_id
CREATE POLICY audit_logs_org_isolation ON audit_logs
  USING (org_id = current_setting('app.current_org_id')::uuid);
