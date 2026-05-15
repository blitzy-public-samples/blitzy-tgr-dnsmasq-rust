#!/usr/bin/env python3
"""
sonar_pipeline.py

Harvest the SonarQube issue set (Directive 4) and normalize each issue to the
user-specified 5-field schema (Directive 5) of the Agent Action Plan for the
blitzy-tgr-dnsmasq-rust security-tool comparison (Config I).

Each safeguard called out in the Checkpoint 1 review report (rows 16..22 of
the AAP Compliance Matrix) is tagged "CR1-#" in the code below so a reviewer
can cross-reference the implementation to the audit requirement.

Module entry points:
  fetch_issues_page(...)   Single page of /api/issues/search.
  harvest_issues(...)      Paginated harvest with paging.total >= 10000
                           fallback to per-subdirectory sub-queries.
  CweResolver.resolve(...) Memoized CWE cascade: tag scan first, then
                           /api/rules/show fallback, then CWE-UNKNOWN.
  normalize_issue(...)     5-field record construction.
  normalize_severity(...)  Strict dictionary remap. Hard-errors on unknown.
  normalize_component(...) Strips the project-key prefix and .rs filter.
  normalize_line(...)      Positive-integer filter; returns None to exclude.
  truncate_description(.)  Unicode code-point truncation to 200 chars.
  write_findings(...)      Minified UTF-8 JSON, single line, trailing \\n.

CLI:
  python3 sonar_pipeline.py \\
      --host-url http://localhost:9000 \\
      --login admin --password admin \\
      --project-key blitzy-tgr-dnsmasq-rust \\
      --output findings-config-i.json

  python3 sonar_pipeline.py \\
      --dry-run-issues /tmp/raw-issues.json \\
      --dry-run-rules  /tmp/rules.json \\
      --project-key blitzy-tgr-dnsmasq-rust \\
      --output /tmp/findings.json
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# CR1-16: Severity remap.
#
# The dictionary is exactly the user-supplied table from the prompt:
#   blocker/critical -> critical
#   major            -> high
#   minor            -> medium
#   info             -> low
#
# Any input value not in this set is treated as a SonarQube API contract
# change and raises a hard error so the normalization step does not silently
# emit out-of-schema severities.
# ---------------------------------------------------------------------------
SEVERITY_REMAP: Dict[str, str] = {
    "BLOCKER":  "critical",
    "CRITICAL": "critical",
    "MAJOR":    "high",
    "MINOR":    "medium",
    "INFO":     "low",
}

# Project-key prefix stripped from issue.component before recording the file
# path. Bound here so the test pipeline can reuse the same constant.
PROJECT_KEY_DEFAULT = "blitzy-tgr-dnsmasq-rust"

# Regex for the CWE tag scan (CR1-17 step 1).
CWE_TAG_RE = re.compile(r"^cwe-(\d+)$", re.IGNORECASE)

# Regex for the CWE token in a rule's HTML description (CR1-17 step 2).
CWE_DESC_RE = re.compile(r"CWE-(\d+)")

# Sentinel emitted when neither cascade step yields a CWE identifier (so the
# schema's "every record has all 5 fields populated" invariant is honored).
CWE_UNKNOWN = "CWE-UNKNOWN"

# Maximum description length in Unicode code points (D5 schema requirement).
DESCRIPTION_MAX_CHARS = 200

# SonarQube API constants.
ISSUES_PAGE_SIZE_DEFAULT = 500        # CR1-21
ISSUES_PAGE_SIZE_HARD_CAP = 10_000    # CR1-22 trigger threshold
ISSUE_TYPES = "VULNERABILITY,BUG"
REQUEST_TIMEOUT_S = 30


# ---------------------------------------------------------------------------
# HTTP helper.
# ---------------------------------------------------------------------------

def _build_basic_auth_header(login: str, password: str) -> Dict[str, str]:
    """Return an HTTP Basic auth header for SonarQube.

    The SonarQube Community Build accepts ``admin/admin`` Basic auth for
    programmatic API calls on first boot, even though the UI forces a
    password change at first interactive login (per the AAP §0.2.2 research
    log).
    """
    raw = f"{login}:{password}".encode("utf-8")
    return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}


def _http_get_json(
    url: str,
    auth_header: Optional[Dict[str, str]] = None,
    timeout_s: int = REQUEST_TIMEOUT_S,
) -> Dict[str, Any]:
    """GET ``url`` and parse the response as JSON.

    Both a connect-style timeout and a whole-request timeout are enforced by
    ``urllib`` via the ``timeout`` parameter; the SonarQube API documentation
    notes that all endpoints respond well under five seconds for properly
    sized projects, so 30 s is a generous ceiling.
    """
    headers = {"Accept": "application/json"}
    if auth_header:
        headers.update(auth_header)
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        body = response.read()
    return json.loads(body.decode("utf-8"))


# ---------------------------------------------------------------------------
# CR1-21 / CR1-22: Issue harvest.
# ---------------------------------------------------------------------------

def fetch_issues_page(
    host_url: str,
    project_key: str,
    page: int,
    page_size: int,
    auth_header: Optional[Dict[str, str]],
    component_keys: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Fetch a single page from /api/issues/search.

    Implements CR1-21: the type filter is the exact ``VULNERABILITY,BUG``
    string from the user directive, the page size defaults to 500, and the
    component filter scopes the search to the project (or a subset, when
    the 10k fallback path drills into sub-components).
    """
    component_filter = (
        ",".join(component_keys) if component_keys else project_key
    )
    query = {
        "componentKeys": component_filter,
        "types": ISSUE_TYPES,
        "ps": str(page_size),
        "p": str(page),
    }
    url = f"{host_url.rstrip('/')}/api/issues/search?{urllib.parse.urlencode(query)}"
    return _http_get_json(url, auth_header=auth_header)


def harvest_issues(
    host_url: str,
    project_key: str,
    auth_header: Optional[Dict[str, str]],
    subcomponents: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Return every VULNERABILITY/BUG issue for ``project_key``.

    Implements CR1-22: if the first page reports ``paging.total`` at or above
    the SonarQube hard cap (10,000), the harvest restarts using the supplied
    ``subcomponents`` list as a series of disjoint ``componentKeys`` queries
    so the full result set can be assembled despite the per-query cap. When
    the cap is not hit, the loop simply paginates ``p=1,2,...`` at
    ``ps=500`` until every issue is collected.
    """
    page = 1
    issues: List[Dict[str, Any]] = []

    first = fetch_issues_page(
        host_url=host_url,
        project_key=project_key,
        page=page,
        page_size=ISSUES_PAGE_SIZE_DEFAULT,
        auth_header=auth_header,
    )

    paging = first.get("paging", {})
    total = int(paging.get("total", 0))
    page_size = int(paging.get("pageSize", ISSUES_PAGE_SIZE_DEFAULT))

    if total >= ISSUES_PAGE_SIZE_HARD_CAP and subcomponents:
        # CR1-22: drop the project-wide page-1 results and re-harvest per
        # sub-component so each sub-query stays under the 10k cap.
        for sub_key in subcomponents:
            issues.extend(_harvest_for_component(
                host_url=host_url,
                project_key=project_key,
                component_key=sub_key,
                auth_header=auth_header,
            ))
        return issues

    issues.extend(first.get("issues", []))

    # Continue paginating page=2..N until we have ``total`` records or the
    # API returns an empty page (defensive: protects against pathological
    # paging metadata).
    while len(issues) < total:
        page += 1
        more = fetch_issues_page(
            host_url=host_url,
            project_key=project_key,
            page=page,
            page_size=ISSUES_PAGE_SIZE_DEFAULT,
            auth_header=auth_header,
        )
        batch = more.get("issues", [])
        if not batch:
            break
        issues.extend(batch)
        # SonarQube enforces p * ps <= 10000; once we are at the cap we
        # cannot paginate further with this filter set, so we stop here.
        if page * page_size >= ISSUES_PAGE_SIZE_HARD_CAP:
            break

    return issues


def _harvest_for_component(
    host_url: str,
    project_key: str,
    component_key: str,
    auth_header: Optional[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Page through /api/issues/search for a single sub-component.

    Helper for the CR1-22 fallback. Identical pagination semantics to
    :func:`harvest_issues` but with a tightened component filter.
    """
    page = 1
    out: List[Dict[str, Any]] = []
    while True:
        resp = fetch_issues_page(
            host_url=host_url,
            project_key=project_key,
            page=page,
            page_size=ISSUES_PAGE_SIZE_DEFAULT,
            auth_header=auth_header,
            component_keys=[component_key],
        )
        batch = resp.get("issues", [])
        if not batch:
            break
        out.extend(batch)
        total = int(resp.get("paging", {}).get("total", 0))
        if len(out) >= total or page * ISSUES_PAGE_SIZE_DEFAULT >= ISSUES_PAGE_SIZE_HARD_CAP:
            break
        page += 1
    return out


# ---------------------------------------------------------------------------
# CR1-17: CWE cascade with memoization.
# ---------------------------------------------------------------------------

class CweResolver:
    """Two-step CWE cascade with per-rule memoization.

    Step 1 — tag scan: looks at ``issue.tags[]`` for an entry matching the
    regex ``^cwe-(\\d+)$``. The literal ``cwe`` tag (without a numeric ID)
    is rejected by this regex on purpose: it signals "this rule relates to
    CWE" without naming a specific identifier, so the cascade must fall
    through to step 2.

    Step 2 — rule description fallback: GET ``/api/rules/show?key=<rule>``
    and extract the first ``CWE-\\d+`` token from the rule's ``htmlDesc``
    field. The response is memoized by rule key for the lifetime of the
    resolver so concurrent issues sharing a rule trigger at most one call.

    Step 3 — sentinel: when neither step yields a result, ``CWE-UNKNOWN``
    is returned so the 5-field schema invariant is preserved.
    """

    def __init__(
        self,
        host_url: str,
        auth_header: Optional[Dict[str, str]] = None,
        rule_fixtures: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self._host_url = host_url.rstrip("/")
        self._auth_header = auth_header
        self._cache: Dict[str, Optional[str]] = {}
        # rule_fixtures lets the dry-run path inject canned /api/rules/show
        # responses without hitting the network.
        self._rule_fixtures: Dict[str, Dict[str, Any]] = rule_fixtures or {}

    @staticmethod
    def _scan_tags(tags: Iterable[str]) -> Optional[str]:
        """Return the first ``CWE-<digits>`` identifier in ``tags``, or None."""
        for tag in tags or []:
            match = CWE_TAG_RE.match(tag)
            if match:
                return f"CWE-{match.group(1)}"
        return None

    @staticmethod
    def _scan_html_desc(html_desc: str) -> Optional[str]:
        """Return the first ``CWE-<digits>`` token in ``html_desc`` or None."""
        if not html_desc:
            return None
        match = CWE_DESC_RE.search(html_desc)
        if match:
            return f"CWE-{match.group(1)}"
        return None

    def _lookup_rule_cwe(self, rule_key: str) -> Optional[str]:
        """Fetch the rule's htmlDesc and extract a CWE token. Memoized."""
        if rule_key in self._cache:
            return self._cache[rule_key]

        # Dry-run path: serve from fixtures rather than calling the API.
        if rule_key in self._rule_fixtures:
            payload = self._rule_fixtures[rule_key]
        else:
            url = f"{self._host_url}/api/rules/show?{urllib.parse.urlencode({'key': rule_key})}"
            try:
                payload = _http_get_json(url, auth_header=self._auth_header)
            except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
                # Network blip or malformed payload: cache None so we do not
                # retry for the same rule in this run.
                self._cache[rule_key] = None
                return None

        rule = payload.get("rule") if isinstance(payload, dict) else None
        html_desc = (rule or {}).get("htmlDesc", "")
        cwe = self._scan_html_desc(html_desc)
        self._cache[rule_key] = cwe
        return cwe

    def resolve(self, issue: Dict[str, Any]) -> str:
        """Apply the full three-step cascade to a single issue."""
        # Step 1: tag scan.
        tagged = self._scan_tags(issue.get("tags") or [])
        if tagged:
            return tagged

        # Step 2: rule description fallback.
        rule_key = issue.get("rule") or ""
        if rule_key:
            from_desc = self._lookup_rule_cwe(rule_key)
            if from_desc:
                return from_desc

        # Step 3: sentinel.
        return CWE_UNKNOWN

    @property
    def rule_lookup_count(self) -> int:
        """Number of distinct rule keys that triggered a /api/rules/show call."""
        return len(self._cache)


# ---------------------------------------------------------------------------
# CR1-16/18/19/20: Field normalization helpers.
# ---------------------------------------------------------------------------

def normalize_severity(raw: Optional[str]) -> str:
    """Map SonarQube severity to the user-specified vocabulary.

    Raises ``ValueError`` on any value not in :data:`SEVERITY_REMAP`. This is
    intentional: an unrecognized severity indicates a SonarQube API contract
    change and we want the pipeline to fail loudly rather than silently emit
    an out-of-schema record.
    """
    if not isinstance(raw, str):
        raise ValueError(
            f"Issue severity must be a string; got {type(raw).__name__}"
        )
    key = raw.upper()
    try:
        return SEVERITY_REMAP[key]
    except KeyError as exc:
        raise ValueError(
            f"Unknown SonarQube severity '{raw}'. Refusing to emit a record "
            f"with an out-of-schema severity value."
        ) from exc


def normalize_component(component: Optional[str], project_key: str) -> Optional[str]:
    """Strip ``<project_key>:`` from ``component`` and apply the .rs filter.

    Returns ``None`` for components that are project-level (no colon), that
    do not begin with the expected prefix, that resolve to an empty path,
    or that do not end with ``.rs``. The caller treats ``None`` as a signal
    to drop the issue from the output.
    """
    if not isinstance(component, str) or not component:
        return None

    prefix = f"{project_key}:"
    if not component.startswith(prefix):
        # An issue raised on a project-level or unrelated component cannot
        # be expressed as a file-level record under our schema.
        return None

    rel = component[len(prefix):]
    if not rel:
        return None

    # CR1-18: keep only Rust source files. The AAP type filter
    # (VULNERABILITY,BUG) already limits non-Rust noise but the project
    # also contains TOML/MD inputs that the analyzer could in theory
    # touch; this guard is a belt-and-braces filter so the final artifact
    # carries only .rs file paths.
    if not rel.endswith(".rs"):
        return None

    return rel


def normalize_line(value: Any) -> Optional[int]:
    """Return ``value`` coerced to a positive int, or ``None``.

    SonarQube emits ``line`` as an integer for file-level issues and omits
    it for project-level issues. The user schema requires an integer line,
    so any issue without a positive ``line`` is excluded by returning
    ``None`` (the caller drops the record).
    """
    if value is None:
        return None
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        return None
    return coerced if coerced > 0 else None


def truncate_description(message: Optional[str]) -> str:
    """Truncate to at most :data:`DESCRIPTION_MAX_CHARS` Unicode code points.

    The slice is on the string (code-point indices), not on the encoded
    bytes, so the resulting value remains valid UTF-8 even when the message
    contains multi-byte characters. No ellipsis is appended: the user
    directive specifies a strict character cap, not a visual indicator.
    Internal whitespace runs are collapsed to single spaces before
    truncation so that trailing whitespace from line breaks does not pad
    out the cap.
    """
    if message is None:
        return ""
    collapsed = " ".join(str(message).split())
    return collapsed[:DESCRIPTION_MAX_CHARS]


# ---------------------------------------------------------------------------
# Per-issue normalization.
# ---------------------------------------------------------------------------

def normalize_issue(
    issue: Dict[str, Any],
    project_key: str,
    cwe_resolver: CweResolver,
) -> Optional[Dict[str, Any]]:
    """Convert a single SonarQube issue to a 5-field record.

    Returns ``None`` when the issue cannot be expressed in the output schema
    (no file-level component, no positive line, non-Rust path). The caller
    skips records that come back as ``None``.

    Raises ``ValueError`` on an unknown severity per :func:`normalize_severity`.
    """
    file_path = normalize_component(issue.get("component"), project_key)
    if file_path is None:
        return None

    line = normalize_line(issue.get("line"))
    if line is None:
        return None

    record = {
        "file":        file_path,
        "line":        line,
        "severity":    normalize_severity(issue.get("severity")),
        "cwe":         cwe_resolver.resolve(issue),
        "description": truncate_description(issue.get("message")),
    }
    return record


def normalize_all(
    issues: Sequence[Dict[str, Any]],
    project_key: str,
    cwe_resolver: CweResolver,
) -> Tuple[List[Dict[str, Any]], List[Tuple[str, Dict[str, Any]]]]:
    """Normalize an issue list, returning (records, skipped).

    ``skipped`` is a list of ``(reason, raw_issue)`` tuples for any record
    that was excluded from the output. The decision log captures the count
    by reason.
    """
    records: List[Dict[str, Any]] = []
    skipped: List[Tuple[str, Dict[str, Any]]] = []

    for issue in issues:
        component = issue.get("component")
        if not isinstance(component, str) or f"{project_key}:" not in component:
            skipped.append(("non-project-component", issue))
            continue
        if normalize_component(component, project_key) is None:
            # Distinguish "non-rust path" from "no component prefix" so the
            # caller can report which filter dropped the record.
            rel = component.split(":", 1)[1] if ":" in component else ""
            if rel and not rel.endswith(".rs"):
                skipped.append(("non-rust-path", issue))
            else:
                skipped.append(("empty-path", issue))
            continue
        if normalize_line(issue.get("line")) is None:
            skipped.append(("non-positive-line", issue))
            continue

        record = normalize_issue(issue, project_key, cwe_resolver)
        if record is None:
            # Defensive: should not happen given the per-field checks above.
            skipped.append(("filtered-during-normalize", issue))
            continue
        records.append(record)

    return records, skipped


# ---------------------------------------------------------------------------
# CR1: JSON serialization and write.
# ---------------------------------------------------------------------------

def write_findings(records: Sequence[Dict[str, Any]], path: str) -> None:
    """Write ``records`` as a minified single-line JSON array.

    Format guarantees:
      * Outermost value is always a JSON array (never ``null``).
      * ``separators=(",", ":")`` removes whitespace between tokens.
      * UTF-8 encoding, no BOM, single trailing ``\\n`` so that
        ``wc -l`` returns 1 (a file with no trailing newline reports 0
        lines from wc).
      * The empty-result case writes the literal three-byte sequence
        ``[]\\n``.
    """
    payload = json.dumps(list(records), separators=(",", ":"), ensure_ascii=False)
    with open(path, "wb") as fh:
        fh.write(payload.encode("utf-8"))
        fh.write(b"\n")


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Harvest and normalize SonarQube findings (Config I).",
    )
    parser.add_argument("--host-url", default="http://localhost:9000")
    parser.add_argument("--login", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--project-key", default=PROJECT_KEY_DEFAULT)
    parser.add_argument(
        "--output",
        required=True,
        help="Path to findings-config-i.json.",
    )
    parser.add_argument(
        "--subcomponent",
        action="append",
        default=[],
        help=(
            "Optional sub-component key (e.g. 'blitzy-tgr-dnsmasq-rust:src') "
            "to use for the paging.total>=10000 fallback. May be repeated."
        ),
    )
    parser.add_argument(
        "--dry-run-issues",
        default=None,
        help=(
            "Path to a JSON file containing a pre-recorded /api/issues/search "
            "response (a dict with an 'issues' array). When set, the network "
            "harvest is bypassed."
        ),
    )
    parser.add_argument(
        "--dry-run-rules",
        default=None,
        help=(
            "Path to a JSON file containing a {rule_key: rule_show_payload} "
            "fixture map for the CWE cascade dry-run. Ignored unless "
            "--dry-run-issues is also set."
        ),
    )
    return parser.parse_args(argv)


def _load_json_file(path: str) -> Any:
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    auth_header = _build_basic_auth_header(args.login, args.password)

    # ---- Harvest --------------------------------------------------------
    if args.dry_run_issues:
        raw_payload = _load_json_file(args.dry_run_issues)
        if isinstance(raw_payload, dict):
            issues = list(raw_payload.get("issues", []))
        elif isinstance(raw_payload, list):
            issues = list(raw_payload)
        else:
            raise ValueError(
                "Dry-run issues file must contain either a JSON object with "
                "an 'issues' key, or a JSON array of issue objects."
            )

        rule_fixtures = (
            _load_json_file(args.dry_run_rules) if args.dry_run_rules else {}
        )
        if not isinstance(rule_fixtures, dict):
            raise ValueError(
                "Dry-run rules file must contain a JSON object mapping rule "
                "keys to /api/rules/show response payloads."
            )

        cwe_resolver = CweResolver(
            host_url=args.host_url,
            auth_header=None,
            rule_fixtures=rule_fixtures,
        )
    else:
        issues = harvest_issues(
            host_url=args.host_url,
            project_key=args.project_key,
            auth_header=auth_header,
            subcomponents=args.subcomponent or None,
        )
        cwe_resolver = CweResolver(
            host_url=args.host_url,
            auth_header=auth_header,
        )

    # ---- Normalize ------------------------------------------------------
    records, skipped = normalize_all(
        issues=issues,
        project_key=args.project_key,
        cwe_resolver=cwe_resolver,
    )

    # ---- Write ----------------------------------------------------------
    write_findings(records, args.output)

    # ---- Telemetry summary ---------------------------------------------
    skipped_counts: Dict[str, int] = {}
    for reason, _ in skipped:
        skipped_counts[reason] = skipped_counts.get(reason, 0) + 1

    print(
        json.dumps(
            {
                "raw_issues_total":   len(issues),
                "normalized_records": len(records),
                "skipped_total":      len(skipped),
                "skipped_by_reason":  skipped_counts,
                "rule_lookups":       cwe_resolver.rule_lookup_count,
                "output_file":        args.output,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
