"""Database table definitions and schema constants for Cipher-Lens."""

CREATE_AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    assessment_id TEXT,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL UNIQUE
);
"""

CREATE_AUDIT_LOG_NO_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
"""

CREATE_AUDIT_LOG_NO_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
"""

CREATE_ASSESSMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    target TEXT NOT NULL,
    scope_id TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}'
);
"""

CREATE_ASSESSMENTS_STATUS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
"""

CREATE_PLAN_STEPS_TABLE = """
CREATE TABLE IF NOT EXISTS plan_steps (
    step_id TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    action_class TEXT NOT NULL,
    target TEXT NOT NULL,
    params TEXT NOT NULL DEFAULT '{}',
    rationale TEXT NOT NULL,
    triggered_by TEXT NOT NULL DEFAULT '[]',
    expected_outcome TEXT NOT NULL,
    nist_phase TEXT NOT NULL,
    idempotency_key TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (assessment_id, step_id),
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);
"""

CREATE_PLAN_STEPS_ASSESSMENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_plan_steps_assessment ON plan_steps(assessment_id);
"""

CREATE_PLAN_STEPS_STATUS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_plan_steps_status ON plan_steps(assessment_id, status);
"""

CREATE_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    status TEXT NOT NULL,
    exit_code INTEGER,
    stdout_artifact_id TEXT,
    stderr_artifact_id TEXT,
    raw_sha256 TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    duration_ms INTEGER,
    error_message TEXT,
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);
"""

CREATE_RUNS_ASSESSMENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_runs_assessment ON runs(assessment_id);
"""

CREATE_RUNS_STEP_INDEX = """
CREATE INDEX IF NOT EXISTS idx_runs_step ON runs(assessment_id, step_id);
"""

CREATE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    title TEXT NOT NULL,
    asset TEXT NOT NULL,
    sources TEXT NOT NULL,
    evidence TEXT NOT NULL,
    inferences TEXT NOT NULL DEFAULT '[]',
    cve TEXT NOT NULL DEFAULT '[]',
    cwe TEXT NOT NULL DEFAULT '[]',
    cvss TEXT,
    tool_severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    status_reason TEXT NOT NULL,
    limitations TEXT NOT NULL DEFAULT '[]',
    risk TEXT,
    validation TEXT,
    correlation_key TEXT NOT NULL,
    related_ids TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (assessment_id, id),
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);
"""

CREATE_FINDINGS_ASSESSMENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
"""

CREATE_FINDINGS_CORRELATION_INDEX = """
CREATE INDEX IF NOT EXISTS idx_findings_correlation ON findings(assessment_id, correlation_key);
"""

CREATE_EVIDENCE_TABLE = """
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    finding_id TEXT,
    source_tool TEXT NOT NULL,
    run_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    locator TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    snippet TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    origin TEXT NOT NULL,
    PRIMARY KEY (assessment_id, id),
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);
"""

CREATE_EVIDENCE_ASSESSMENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_evidence_assessment ON evidence(assessment_id);
"""

CREATE_EVIDENCE_FINDING_INDEX = """
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(assessment_id, finding_id);
"""

CREATE_APPROVALS_TABLE = """
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    action_class TEXT NOT NULL,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    rationale TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    status TEXT NOT NULL,
    decision TEXT,
    decided_by TEXT,
    reason TEXT,
    decided_at TEXT,
    notes TEXT,
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);
"""

CREATE_APPROVALS_ASSESSMENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_approvals_assessment ON approvals(assessment_id);
"""

CREATE_APPROVALS_STEP_INDEX = """
CREATE INDEX IF NOT EXISTS idx_approvals_step ON approvals(assessment_id, step_id);
"""

CREATE_LLM_TRACES_TABLE = """
CREATE TABLE IF NOT EXISTS llm_traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    assessment_id TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_hash TEXT NOT NULL,
    input_summary TEXT NOT NULL,
    output TEXT NOT NULL,
    label TEXT NOT NULL,
    tokens_prompt INTEGER,
    tokens_completion INTEGER,
    latency_ms INTEGER,
    outcome TEXT NOT NULL
);
"""

CREATE_LLM_TRACES_HASH_INDEX = """
CREATE INDEX IF NOT EXISTS idx_llm_traces_prompt_hash ON llm_traces(prompt_hash);
"""

CREATE_LLM_TRACES_ASSESSMENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_llm_traces_assessment ON llm_traces(assessment_id);
"""

SCHEMA_STATEMENTS: list[str] = [
    CREATE_AUDIT_LOG_TABLE,
    CREATE_AUDIT_LOG_NO_UPDATE_TRIGGER,
    CREATE_AUDIT_LOG_NO_DELETE_TRIGGER,
    CREATE_ASSESSMENTS_TABLE,
    CREATE_ASSESSMENTS_STATUS_INDEX,
    CREATE_PLAN_STEPS_TABLE,
    CREATE_PLAN_STEPS_ASSESSMENT_INDEX,
    CREATE_PLAN_STEPS_STATUS_INDEX,
    CREATE_RUNS_TABLE,
    CREATE_RUNS_ASSESSMENT_INDEX,
    CREATE_RUNS_STEP_INDEX,
    CREATE_FINDINGS_TABLE,
    CREATE_FINDINGS_ASSESSMENT_INDEX,
    CREATE_FINDINGS_CORRELATION_INDEX,
    CREATE_EVIDENCE_TABLE,
    CREATE_EVIDENCE_ASSESSMENT_INDEX,
    CREATE_EVIDENCE_FINDING_INDEX,
    CREATE_APPROVALS_TABLE,
    CREATE_APPROVALS_ASSESSMENT_INDEX,
    CREATE_APPROVALS_STEP_INDEX,
    CREATE_LLM_TRACES_TABLE,
    CREATE_LLM_TRACES_HASH_INDEX,
    CREATE_LLM_TRACES_ASSESSMENT_INDEX,
]

# Aliases for convenience and backward/forward compatibility
AUDIT_LOG_TABLE_SQL = CREATE_AUDIT_LOG_TABLE
AUDIT_LOG_NO_UPDATE_TRIGGER_SQL = CREATE_AUDIT_LOG_NO_UPDATE_TRIGGER
AUDIT_LOG_NO_DELETE_TRIGGER_SQL = CREATE_AUDIT_LOG_NO_DELETE_TRIGGER
TABLES_SQL = SCHEMA_STATEMENTS
