"""
Shared tool definitions for all InfraGuard agents.
Each tool is a real function the AI can call to gather structured data.
"""
import json
import re
import hashlib
from datetime import datetime
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Log analysis tools
# ─────────────────────────────────────────────────────────────────────────────

def parse_log_patterns(log_text: str) -> dict[str, Any]:
    """Extract error patterns, timestamps, and frequency from raw logs."""
    lines = log_text.strip().splitlines()
    errors, warnings, patterns = [], [], {}

    error_re = re.compile(r"(ERROR|FATAL|CRITICAL|Exception|Traceback|panic)", re.I)
    warn_re = re.compile(r"(WARN|WARNING|DEPRECATED)", re.I)
    ts_re = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")

    for i, line in enumerate(lines):
        if error_re.search(line):
            errors.append({"line": i + 1, "content": line.strip()[:200]})
        elif warn_re.search(line):
            warnings.append({"line": i + 1, "content": line.strip()[:200]})

        # fingerprint repeated messages
        fingerprint = re.sub(r"\b\d+\b", "N", line)
        fingerprint = re.sub(r"\b[0-9a-f]{8,}\b", "HASH", fingerprint)
        key = fingerprint[:80]
        patterns[key] = patterns.get(key, 0) + 1

    top_patterns = sorted(patterns.items(), key=lambda x: -x[1])[:10]

    return {
        "total_lines": len(lines),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "top_errors": errors[:10],
        "top_warnings": warnings[:5],
        "repeated_patterns": [{"pattern": p, "count": c} for p, c in top_patterns if c > 1],
        "has_timestamps": bool(ts_re.search(log_text)),
    }


def extract_service_dependencies(log_text: str) -> dict[str, Any]:
    """Identify which services/hosts appear in logs and their error rates."""
    host_re = re.compile(r"(?:host|service|endpoint|url|addr)[=:\s]+([a-zA-Z0-9._-]+(?::\d+)?)", re.I)
    http_re = re.compile(r"(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/")
    status_re = re.compile(r"\b(5\d{2}|4\d{2})\b")

    hosts = {}
    endpoints = {}
    bad_statuses = []

    for line in log_text.splitlines():
        for m in host_re.finditer(line):
            h = m.group(1)
            hosts[h] = hosts.get(h, 0) + 1

        for m in http_re.finditer(line):
            e = m.group(1)[:100]
            endpoints[e] = endpoints.get(e, 0) + 1

        for m in status_re.finditer(line):
            bad_statuses.append(m.group(1))

    status_counts: dict[str, int] = {}
    for s in bad_statuses:
        status_counts[s] = status_counts.get(s, 0) + 1

    return {
        "mentioned_services": sorted(hosts.items(), key=lambda x: -x[1])[:10],
        "failing_endpoints": sorted(endpoints.items(), key=lambda x: -x[1])[:5],
        "http_error_codes": status_counts,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Config audit tools
# ─────────────────────────────────────────────────────────────────────────────

def scan_config_security(config_text: str, config_type: str) -> dict[str, Any]:
    """Scan infrastructure config for security anti-patterns."""
    findings = []

    checks = {
        "kubernetes": [
            (r"privileged:\s*true", "CRITICAL", "Container running as privileged"),
            (r"runAsRoot:\s*true|runAsUser:\s*0\b", "HIGH", "Container running as root"),
            (r"hostNetwork:\s*true", "HIGH", "Host network namespace shared"),
            (r"hostPID:\s*true", "HIGH", "Host PID namespace shared"),
            (r"allowPrivilegeEscalation:\s*true", "MEDIUM", "Privilege escalation allowed"),
            (r"readOnlyRootFilesystem:\s*false", "MEDIUM", "Root filesystem is writable"),
            (r"imagePullPolicy:\s*Never|image:\s*\S+:latest\b", "LOW", "Using :latest tag or Never pull policy"),
            (r"resources:\s*\{\}|resources:\s*$", "MEDIUM", "No resource limits defined"),
            (r"(password|secret|token|key)\s*:\s*['\"]?\S+['\"]?", "HIGH", "Possible hardcoded secret"),
        ],
        "terraform": [
            (r"publicly_accessible\s*=\s*true", "HIGH", "Resource is publicly accessible"),
            (r"encrypted\s*=\s*false", "HIGH", "Encryption disabled"),
            (r"(password|secret|token)\s*=\s*['\"](?!var\.)[^'\"]+['\"]", "HIGH", "Hardcoded credential"),
            (r"0\.0\.0\.0/0", "MEDIUM", "Wide-open CIDR range"),
            (r"deletion_protection\s*=\s*false", "MEDIUM", "Deletion protection off"),
            (r"force_destroy\s*=\s*true", "MEDIUM", "Force destroy enabled"),
            (r"skip_final_snapshot\s*=\s*true", "LOW", "Final snapshot skipped on deletion"),
        ],
        "docker": [
            (r"USER\s+root|USER\s+0\b", "HIGH", "Container runs as root"),
            (r"privileged:\s*true", "CRITICAL", "Privileged container"),
            (r"--cap-add\s+ALL", "HIGH", "All Linux capabilities added"),
            (r"network_mode:\s*host", "MEDIUM", "Host network mode"),
            (r"(PASSWORD|SECRET|TOKEN|KEY)\s*=\s*\S+", "HIGH", "Env var may contain secret"),
            (r"COPY\s+\.\s+\.", "LOW", "Copying entire context (may expose secrets)"),
            (r"FROM\s+\S+:latest\b", "LOW", "Using :latest base image"),
        ],
    }

    ctype = config_type.lower()
    applicable = checks.get(ctype, checks["kubernetes"])  # fallback

    for pattern, severity, message in applicable:
        for m in re.finditer(pattern, config_text, re.MULTILINE | re.IGNORECASE):
            line_num = config_text[: m.start()].count("\n") + 1
            findings.append({
                "severity": severity,
                "line": line_num,
                "message": message,
                "snippet": config_text[max(0, m.start()-20):m.end()+20].strip()[:120],
            })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return {
        "config_type": config_type,
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in findings if f["severity"] == "LOW"),
        "findings": findings[:20],
    }


def check_resource_limits(config_text: str) -> dict[str, Any]:
    """Check if K8s workloads have proper resource requests/limits."""
    containers = re.findall(
        r"- name:\s*(\S+).*?(?=- name:|\Z)",
        config_text,
        re.DOTALL,
    )
    results = []
    for i, block in enumerate(containers):
        name_match = re.search(r"- name:\s*(\S+)", block)
        name = name_match.group(1) if name_match else f"container-{i}"
        has_cpu_req = bool(re.search(r"cpu:\s*\S+", block))
        has_mem_req = bool(re.search(r"memory:\s*\S+", block))
        results.append({
            "container": name,
            "has_resource_limits": has_cpu_req and has_mem_req,
            "missing": [r for r, ok in [("cpu", has_cpu_req), ("memory", has_mem_req)] if not ok],
        })
    return {"containers_checked": len(results), "details": results}


# ─────────────────────────────────────────────────────────────────────────────
# Deployment diff tools
# ─────────────────────────────────────────────────────────────────────────────

def analyze_diff_scope(diff_text: str) -> dict[str, Any]:
    """Quantify the blast radius of a deployment diff."""
    added = [l for l in diff_text.splitlines() if l.startswith("+") and not l.startswith("+++")]
    removed = [l for l in diff_text.splitlines() if l.startswith("-") and not l.startswith("---")]

    # detect changed file types
    file_re = re.compile(r"(?:diff --git a/|--- a/|\+\+\+ b/)(\S+)")
    files = list({m.group(1) for m in file_re.finditer(diff_text)})

    infra_files = [f for f in files if any(
        ext in f for ext in [".tf", ".yaml", ".yml", "Dockerfile", ".sh", "k8s", "helm"]
    )]
    db_files = [f for f in files if any(
        kw in f.lower() for kw in ["migration", "schema", "seed", "sql"]
    )]
    secret_files = [f for f in files if any(
        kw in f.lower() for kw in ["secret", ".env", "credential", "vault", "cert"]
    )]

    return {
        "lines_added": len(added),
        "lines_removed": len(removed),
        "change_ratio": round(len(added) / max(len(removed), 1), 2),
        "files_changed": len(files),
        "infrastructure_files": infra_files,
        "database_migration_files": db_files,
        "sensitive_files_touched": secret_files,
        "risk_indicators": {
            "large_change": len(added) + len(removed) > 500,
            "infra_change": len(infra_files) > 0,
            "db_migration": len(db_files) > 0,
            "secret_touched": len(secret_files) > 0,
        },
    }


def detect_breaking_changes(diff_text: str) -> dict[str, Any]:
    """Detect API contract changes, renamed env vars, removed endpoints."""
    breaking = []

    # removed env vars
    for m in re.finditer(r"^-\s*(\w+)=", diff_text, re.MULTILINE):
        breaking.append({"type": "env_var_removed", "value": m.group(1)})

    # API endpoint removed
    for m in re.finditer(r"^-.*(?:@app\.|router\.|route\(|path\()['\"]([^'\"]+)", diff_text, re.MULTILINE):
        breaking.append({"type": "endpoint_removed", "value": m.group(1)})

    # renamed DB column (simplified)
    for m in re.finditer(r"^-\s*(\w+)\s+\w+,?$", diff_text, re.MULTILINE):
        breaking.append({"type": "possible_db_column_removal", "value": m.group(1)})

    return {
        "breaking_change_count": len(breaking),
        "breaking_changes": breaking[:15],
        "rollback_complexity": "HIGH" if len(breaking) > 5 else ("MEDIUM" if len(breaking) > 0 else "LOW"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline / CI tools
# ─────────────────────────────────────────────────────────────────────────────

def parse_pipeline_failure(pipeline_log: str) -> dict[str, Any]:
    """Extract the failing step, exit code, and last N lines before failure."""
    step_re = re.compile(r"(?:Step|STEP|stage|Stage|Job|job)\s+[\d/]+\s*:\s*(.+)", re.I)
    exit_re = re.compile(r"exit\s+(?:code\s+)?(\d+)|returned\s+(\d+)|exited\s+with\s+(\d+)", re.I)
    error_re = re.compile(r"(error|failed|failure|fatal|exception)", re.I)

    lines = pipeline_log.splitlines()
    steps = [m.group(1).strip() for line in lines for m in [step_re.search(line)] if m]
    exits = []
    for line in lines:
        m = exit_re.search(line)
        if m:
            exits.append(m.group(1) or m.group(2) or m.group(3))

    # find last error occurrence
    last_error_idx = 0
    for i, line in enumerate(lines):
        if error_re.search(line):
            last_error_idx = i

    context_start = max(0, last_error_idx - 10)
    error_context = lines[context_start: last_error_idx + 5]

    return {
        "pipeline_steps": steps,
        "last_step": steps[-1] if steps else "unknown",
        "exit_codes": list(set(exits)),
        "failed_at_line": last_error_idx + 1,
        "error_context": error_context,
        "likely_failure_type": _classify_failure(pipeline_log),
    }


def _classify_failure(log: str) -> str:
    classifiers = [
        (r"(oom|out of memory|killed)", "OOM_KILL"),
        (r"(timeout|timed out|deadline exceeded)", "TIMEOUT"),
        (r"(connection refused|connection reset|no route to host)", "NETWORK_ERROR"),
        (r"(permission denied|access denied|forbidden)", "PERMISSION_ERROR"),
        (r"(no space left|disk full)", "DISK_FULL"),
        (r"(test.*fail|assertion.*fail|expect.*fail)", "TEST_FAILURE"),
        (r"(cannot pull|pull access denied|image not found)", "IMAGE_PULL_ERROR"),
        (r"(syntax error|parse error|invalid yaml|json parse)", "CONFIG_SYNTAX_ERROR"),
    ]
    for pattern, label in classifiers:
        if re.search(pattern, log, re.I):
            return label
    return "UNKNOWN"


def get_similar_incidents_mock(error_signature: str) -> dict[str, Any]:
    """Mock knowledge base lookup for similar past incidents."""
    kb = {
        "OOM_KILL": {
            "past_incidents": 3,
            "common_causes": ["Memory leak in app", "Insufficient memory limits", "Large batch job"],
            "typical_fix": "Increase memory limits or optimize memory usage in the service",
            "avg_resolution_time": "45 minutes",
        },
        "TIMEOUT": {
            "past_incidents": 7,
            "common_causes": ["Slow DB query", "Downstream service degraded", "Network latency spike"],
            "typical_fix": "Check DB slow query log and upstream service health",
            "avg_resolution_time": "30 minutes",
        },
        "NETWORK_ERROR": {
            "past_incidents": 5,
            "common_causes": ["DNS failure", "Service not started", "Wrong port/host config"],
            "typical_fix": "Verify service discovery and network policies",
            "avg_resolution_time": "20 minutes",
        },
        "TEST_FAILURE": {
            "past_incidents": 12,
            "common_causes": ["Flaky test", "Missing fixture", "Env var not set in CI"],
            "typical_fix": "Check test logs for assertion details, review recent code changes",
            "avg_resolution_time": "60 minutes",
        },
        "IMAGE_PULL_ERROR": {
            "past_incidents": 2,
            "common_causes": ["Wrong registry credentials", "Image tag does not exist"],
            "typical_fix": "Verify image tag and registry auth secret in namespace",
            "avg_resolution_time": "15 minutes",
        },
    }
    return kb.get(error_signature, {
        "past_incidents": 0,
        "common_causes": ["Unknown"],
        "typical_fix": "Manual investigation required",
        "avg_resolution_time": "Unknown",
    })


# ─────────────────────────────────────────────────────────────────────────────
# Tool registry (name → callable)
# ─────────────────────────────────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, Any] = {
    "parse_log_patterns": parse_log_patterns,
    "extract_service_dependencies": extract_service_dependencies,
    "scan_config_security": scan_config_security,
    "check_resource_limits": check_resource_limits,
    "analyze_diff_scope": analyze_diff_scope,
    "detect_breaking_changes": detect_breaking_changes,
    "parse_pipeline_failure": parse_pipeline_failure,
    "get_similar_incidents_mock": get_similar_incidents_mock,
}


def execute_tool(name: str, tool_input: dict) -> str:
    fn = TOOL_REGISTRY.get(name)
    if not fn:
        return json.dumps({"error": f"Tool '{name}' not found"})
    try:
        result = fn(**tool_input)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})
