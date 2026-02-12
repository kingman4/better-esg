DROP POLICY IF EXISTS audit_logs_org_isolation ON audit_logs;
DROP POLICY IF EXISTS submission_files_org_isolation ON submission_files;
DROP POLICY IF EXISTS submissions_org_isolation ON submissions;

ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE submission_files DISABLE ROW LEVEL SECURITY;
ALTER TABLE submissions DISABLE ROW LEVEL SECURITY;
