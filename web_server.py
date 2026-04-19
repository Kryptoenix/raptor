#!/usr/bin/env python3
"""
RAPTOR Web Server

Provides a browser-based UI for RAPTOR:
  1. Upload a ZIP of the target repository
  2. Choose analysis mode (scan / fuzz / agentic / codeql)
  3. Monitor live log output while raptor runs
  4. View structured results (findings, exploits, patches, JSON)

Usage:
    python3 web_server.py [--host 127.0.0.1] [--port 5000] [--debug]

Security notes:
  - ZIP extraction is protected against zip-slip (path traversal)
  - All working directories are isolated under WORK_ROOT
  - No shell=True subprocess calls
  - Binary paths passed to AFL++ are relative to the extracted repo
"""

import argparse
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, redirect, render_template, request, url_for

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

RAPTOR_ROOT = Path(__file__).resolve().parent
WORK_ROOT = RAPTOR_ROOT / "web_work"     # isolated dir for all upload jobs
JOB_REGISTRY = WORK_ROOT / "jobs.json"   # persisted job index, survives restarts
JOBS: Dict[str, "Job"] = {}              # in-memory job registry (loaded from JOB_REGISTRY on startup)
MAX_UPLOAD_MB = 200
ALLOWED_MODES = {"webapp", "binary", "scan", "fuzz", "agentic", "codeql", "llmscan"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("raptor-web")

app = Flask(__name__, template_folder=str(RAPTOR_ROOT / "templates"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


# Register template globals at module level so they are always available
# regardless of how the app is launched (python web_server.py, flask run, gunicorn, tests).
@app.context_processor
def _inject_globals():
    return {"max_mb": MAX_UPLOAD_MB}


# ---------------------------------------------------------------------------
# Job persistence (survives server restarts)
# ---------------------------------------------------------------------------

def _persist_job(job: "Job") -> None:
    """
    Write/update this job's metadata to JOB_REGISTRY so it survives restarts.

    We store only the fields needed to reconstruct the job list on the next
    startup: job_id, mode, status, work_dir path, started_at, finished_at.
    Log lines and results are re-read from disk on demand, so we don't need
    to store them here (and they can be large).
    """
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        # Read existing registry
        registry: Dict[str, Any] = {}
        if JOB_REGISTRY.exists():
            try:
                registry = json.loads(JOB_REGISTRY.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                registry = {}

        registry[job.job_id] = {
            "job_id":      job.job_id,
            "mode":        job.mode,
            "status":      job.status,
            "work_dir":    str(job.work_dir),
            "started_at":  job.started_at,
            "finished_at": job.finished_at,
            "return_code": job.return_code,
        }

        JOB_REGISTRY.write_text(
            json.dumps(registry, indent=2),
            encoding="utf-8",
        )
    except Exception as exc:
        log.warning("Failed to persist job %s: %s", job.job_id, exc)


def _load_persisted_jobs() -> None:
    """
    On startup, reconstruct Job objects from JOB_REGISTRY for every job whose
    work_dir still exists on disk.  Jobs whose directories have been deleted
    (e.g. manual cleanup) are silently skipped.

    Reconstructed jobs always have status 'done' or 'error' — any job that
    was 'running' when the server died is marked 'error' (interrupted).
    """
    if not JOB_REGISTRY.exists():
        return

    try:
        registry: Dict[str, Any] = json.loads(
            JOB_REGISTRY.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not load job registry: %s", exc)
        return

    loaded = 0
    for entry in registry.values():
        job_id   = entry.get("job_id", "")
        work_dir = Path(entry.get("work_dir", ""))

        if not job_id or not work_dir.exists():
            continue  # directory was deleted — skip silently

        # Reconstruct a minimal Job object (upload_path may not exist any more)
        upload_path = work_dir / "upload.zip"
        job = Job(
            job_id=job_id,
            mode=entry.get("mode", "unknown"),
            upload_path=upload_path,
            work_dir=work_dir,
            extra_args=[],
        )
        job.started_at  = entry.get("started_at")
        job.finished_at = entry.get("finished_at")
        job.return_code = entry.get("return_code")

        # Any job that appeared 'running' when server died is now interrupted
        status = entry.get("status", "done")
        job.status = "error" if status == "running" else status

        # Restore repo_dir so collect_results() can find output files
        repo_dir_candidate = work_dir / "repo"
        if repo_dir_candidate.exists():
            children = [c for c in repo_dir_candidate.iterdir() if not c.name.startswith(".")]
            job.repo_dir = children[0] if len(children) == 1 and children[0].is_dir() else repo_dir_candidate

        JOBS[job_id] = job
        loaded += 1

    if loaded:
        log.info("Restored %d job(s) from previous session", loaded)


# ---------------------------------------------------------------------------
# Job model
# ---------------------------------------------------------------------------

class Job:
    """Represents a single RAPTOR analysis run."""

    def __init__(
        self,
        job_id: str,
        mode: str,
        upload_path: Path,
        work_dir: Path,
        extra_args: List[str],
    ) -> None:
        self.job_id = job_id
        self.mode = mode
        self.upload_path = upload_path   # original ZIP
        self.work_dir = work_dir         # extracted repo lives here
        self.repo_dir: Optional[Path] = None   # set after extraction
        self.extra_args = extra_args
        self.status = "pending"          # pending | running | done | error | killed
        self.log_lines: List[str] = []
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.return_code: Optional[int] = None
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None  # live subprocess handle for kill support

    # ── log helpers ──────────────────────────────────────────────
    def append_log(self, line: str) -> None:
        with self._lock:
            self.log_lines.append(line)
        # Append to the persistent log file so the output survives server restarts.
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass  # non-fatal: in-memory log still works

    def get_log(self) -> str:
        with self._lock:
            lines = list(self.log_lines)
        if lines:
            return "\n".join(lines)
        # After a server restart log_lines is empty; read from disk instead.
        try:
            if self.log_file.exists():
                return self.log_file.read_text(encoding="utf-8", errors="replace").rstrip()
        except OSError:
            pass
        return ""

    # ── kill ──────────────────────────────────────────────────────
    def kill(self) -> bool:
        """
        Terminate the running subprocess and ALL its children.

        Because we launch raptor with start_new_session=True, the process
        becomes the leader of a new session/process group.  Sending SIGTERM
        to the process group (os.killpg) ensures semgrep workers, afl-fuzz,
        sub-agents and any other child processes are also terminated — not
        just the raptor.py wrapper.
        """
        import signal as _signal
        with self._lock:
            proc = self._proc
        if proc is None or proc.poll() is not None:
            return False  # already finished

        try:
            pgid = os.getpgid(proc.pid)
        except (ProcessLookupError, PermissionError):
            pgid = None

        try:
            if pgid is not None:
                # Kill entire process group (raptor + all spawned children)
                os.killpg(pgid, _signal.SIGTERM)
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    os.killpg(pgid, _signal.SIGKILL)
            else:
                # Fallback: single-process kill
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()

            self.status = "killed"
            self.finished_at = time.time()
            with self._lock:
                self.log_lines.append("[raptor-web] ✗ Job killed by user")
            _persist_job(self)
            return True

        except Exception as exc:
            log.warning("kill() failed for job %s: %s", self.job_id, exc)
            return False

    # ── duration ─────────────────────────────────────────────────
    @property
    def duration(self) -> Optional[float]:
        if self.started_at is None:
            return None
        if self.finished_at is not None:
            # Job completed: return the fixed elapsed time regardless of
            # when we're called (avoids ever-growing duration after restart).
            return self.finished_at - self.started_at
        if self.status == "running":
            # Job still live: show elapsed time so far.
            return time.time() - self.started_at
        # Job ended abnormally without finished_at being set (e.g. interrupted
        # by SIGKILL before the finally block ran). Return None so the UI
        # shows "—" rather than a nonsensical growing number.
        return None

    # ── output dir (where raptor writes results) ─────────────────
    @property
    def out_dir(self) -> Path:
        return self.work_dir / "out"

    @property
    def log_file(self) -> Path:
        """Path to the persistent log file for this job."""
        return self.work_dir / "raptor.log"

    # ── collect result files ──────────────────────────────────────
    def collect_results(self) -> Dict[str, Any]:
        """
        Scan out_dir for reports, findings, exploits, and patches.

        Priority order for structured findings:
          1. orchestrated_report.json  — richest: LLM analysis, exploits, patches inline
          2. raptor_agentic_report.json — top-level agentic summary
          3. autonomous_analysis_report.json — sequential LLM results
          4. Loose exploit/patch files from exploits/ patches/ dirs
        """
        results: Dict[str, Any] = {
            "findings": [],
            "exploits": [],
            "patches": [],
            "cross_groups": [],
            "_raw_json": None,
        }

        if not self.out_dir.exists():
            return results

        # ── 1. orchestrated_report.json (preferred) ───────────────────────
        orch_path = self.out_dir / "orchestrated_report.json"
        if not orch_path.exists():
            # Also look one level deeper (agentic puts it directly in out_dir)
            for candidate in self.out_dir.rglob("orchestrated_report.json"):
                orch_path = candidate
                break

        if orch_path.exists():
            try:
                with open(orch_path) as f:
                    orch = json.load(f)
                results["_raw_json"] = orch
                results["findings"] = _parse_orchestrated_findings(orch, self.out_dir)
                results["cross_groups"] = _parse_cross_groups(orch, self.out_dir)
            except Exception as exc:
                log.warning("Failed to parse orchestrated_report.json: %s", exc)

        # ── 1b. Supplement with LLM-only findings from merged_report.json ──
        # orchestrated_report only contains Semgrep/CodeQL findings that went
        # through LLM analysis. merged_report may contain additional LLM-only
        # findings (from llmscan) that the orchestrator never saw.
        merged_path = self.out_dir / "merged_report.json"
        if results["findings"] and merged_path.exists():
            try:
                with open(merged_path) as f:
                    merged_data = json.load(f)
                merged_items = merged_data.get("results") or []
                if isinstance(merged_items, list) and merged_items:
                    # Only add findings whose source is exclusively "llmscan"
                    # (i.e. not already covered by SARIF/orchestrated findings)
                    _existing_keys = set()
                    for f in results["findings"]:
                        # Build a dedup key from file+line+rule
                        _fpath = (f.get("file_path") or f.get("file") or "").lower()
                        _line = f.get("start_line") or f.get("line") or 0
                        _rule = (f.get("rule_id") or f.get("id") or "").lower()
                        _existing_keys.add((_fpath, int(_line), _rule))
                        # Also match by filename only (SARIF paths may be absolute)
                        _fname = _fpath.rsplit("/", 1)[-1] if "/" in _fpath else _fpath
                        _existing_keys.add((_fname, int(_line), _rule))

                    llm_only_added = 0
                    for mf in merged_items:
                        sources = mf.get("sources") or []
                        # Only supplement with findings not from SARIF tools
                        if sources != ["llmscan"]:
                            continue
                        _mpath = (mf.get("file_path") or "").lower()
                        _mline = int(mf.get("start_line") or 0)
                        _mrule = (mf.get("rule_id") or "").lower()
                        _mfname = _mpath.rsplit("/", 1)[-1] if "/" in _mpath else _mpath
                        if (_mpath, _mline, _mrule) in _existing_keys:
                            continue
                        if (_mfname, _mline, _mrule) in _existing_keys:
                            continue
                        results["findings"].append(_normalise_finding(mf))
                        llm_only_added += 1

                    if llm_only_added > 0:
                        log.info("Supplemented %d LLM-only findings from merged_report.json",
                                 llm_only_added)
            except Exception as exc:
                log.warning("Failed to supplement from merged_report.json: %s", exc)

        # ── 2. merged_report.json (LLM scan + SARIF merge, any mode) ───────
        # Produced by _run_llmscan_phase after scan/agentic/codeql or by
        # standalone llmscan mode. Contains the richest merged finding set.
        if not results["findings"]:
            merged_path = self.out_dir / "merged_report.json"
            if merged_path.exists():
                try:
                    with open(merged_path) as f:
                        merged_data = json.load(f)
                    items = merged_data.get("results") or []
                    if isinstance(items, list) and items:
                        results["findings"] = [_normalise_finding(f) for f in items]
                        if results["_raw_json"] is None:
                            results["_raw_json"] = merged_data
                except Exception as exc:
                    log.warning("Failed to parse merged_report.json: %s", exc)

        # ── 3. raptor_agentic_report.json fallback ────────────────────────
        if not results["findings"]:
            agentic_path = self.out_dir / "raptor_agentic_report.json"
            if agentic_path.exists():
                try:
                    with open(agentic_path) as f:
                        agentic = json.load(f)
                    if results["_raw_json"] is None:
                        results["_raw_json"] = agentic
                    # findings live inside scan.findings or analysis.results
                    for key in ("findings", "results"):
                        items = (agentic.get("scan") or {}).get(key) or agentic.get(key)
                        if isinstance(items, list) and items:
                            results["findings"] = [_normalise_finding(f) for f in items]
                            break
                except Exception as exc:
                    log.warning("Failed to parse raptor_agentic_report.json: %s", exc)

        # ── 4. autonomous_analysis_report.json fallback ───────────────────
        if not results["findings"]:
            for auto_path in self.out_dir.rglob("autonomous_analysis_report.json"):
                try:
                    with open(auto_path) as f:
                        auto = json.load(f)
                    if results["_raw_json"] is None:
                        results["_raw_json"] = auto
                    items = auto.get("results") or auto.get("findings") or []
                    if isinstance(items, list):
                        results["findings"] = [_normalise_finding(f) for f in items]
                    break
                except Exception as exc:
                    log.warning("Failed to parse autonomous_analysis_report.json: %s", exc)

        # ── 5. Loose exploit files from exploits/ dirs ────────────────────
        # Only collect files not already captured inline in findings
        inline_exploit_ids = {
            f.get("finding_id") or f.get("rule_id", "")
            for f in results["findings"]
            if f.get("exploit_code")
        }

        for ef in sorted(self.out_dir.rglob("*")):
            if not ef.is_file():
                continue
            if "exploit" not in ef.parts and "exploit" not in ef.name:
                continue
            if ef.suffix not in {".py", ".cpp", ".c", ".sh", ".rb", ".js"}:
                continue
            # Skip if this exploit belongs to a finding already shown inline
            stem = ef.stem  # e.g. "injection-1_exploit"
            if any(eid and eid in stem for eid in inline_exploit_ids):
                continue
            try:
                results["exploits"].append({
                    "name": ef.name,
                    "file": str(ef.relative_to(self.out_dir)),
                    "code": ef.read_text(errors="replace")[:10000],
                })
            except Exception:
                pass

        # ── 6. Loose patch files from patches/ dirs ───────────────────────
        inline_patch_ids = {
            f.get("finding_id") or f.get("rule_id", "")
            for f in results["findings"]
            if f.get("patch_code")
        }

        for pf in sorted(self.out_dir.rglob("*")):
            if not pf.is_file():
                continue
            if "patch" not in pf.parts and "patch" not in pf.name:
                continue
            if pf.suffix not in {".md", ".txt", ".patch", ".diff"}:
                continue
            stem = pf.stem
            if any(pid and pid in stem for pid in inline_patch_ids):
                continue
            try:
                results["patches"].append({
                    "name": pf.name,
                    "file": str(pf.relative_to(self.out_dir)),
                    "content": pf.read_text(errors="replace")[:10000],
                })
            except Exception:
                pass

        return results

    def build_summary(self) -> Dict[str, Any]:
        """Build a high-level summary dict for the results page."""
        results = self.collect_results()
        raw = results.get("_raw_json") or {}

        summary: Dict[str, Any] = {}

        if self.duration is not None:
            summary["duration"] = self.duration

        # Pull counts from the richest source available.
        # orchestrated_report has top-level exploitable/exploits_generated/patches_generated.
        # raptor_agentic_report nests them under analysis.{}.
        # merged_report (llmscan) has total_findings from len(results).
        for key in ("total_findings", "exploitable", "exploits_generated",
                    "patches_generated", "total_crashes", "binary", "repo"):
            val = raw.get(key)
            if val is None:
                # Try nested analysis block (raptor_agentic_report shape)
                val = (raw.get("analysis") or {}).get(key)
            if val is None and key == "total_findings":
                # merged_report: derive from results list length
                items = raw.get("results")
                if isinstance(items, list):
                    val = len(items)
            if val is not None:
                summary[key] = val

        # Surface llmscan source breakdown if present
        src = raw.get("source_breakdown") or {}
        if src:
            summary["llm_only"]      = src.get("llm_only", 0)
            summary["confirmed_both"] = src.get("confirmed_both", 0)
            summary["sarif_only"]    = src.get("sarif_only", 0)

        # Derive from orchestration block if present
        orch = raw.get("orchestration") or {}
        if "total_findings" not in summary:
            dispatched = orch.get("findings_dispatched")
            if dispatched is not None:
                summary["total_findings"] = dispatched
        if "exploitable" not in summary:
            exploitable = orch.get("findings_exploitable") or raw.get("exploitable")
            if exploitable is not None:
                summary["exploitable"] = exploitable

        # Fallback counts from collected artifacts
        if "total_findings" not in summary and results.get("findings"):
            summary["total_findings"] = len(results["findings"])
        # If LLM-only findings were supplemented, the actual count may be higher
        # than what orchestrated_report reported — prefer the real count.
        if results.get("findings") and len(results["findings"]) > summary.get("total_findings", 0):
            summary["total_findings"] = len(results["findings"])
        if "exploits_generated" not in summary and results.get("exploits"):
            summary["exploits_generated"] = len(results["exploits"])
        if "patches_generated" not in summary and results.get("patches"):
            summary["patches_generated"] = len(results["patches"])

        # Repo path (show relative name only, not server path)
        if "repo" not in summary and self.repo_dir:
            summary["repo"] = self.repo_dir.name

        return summary


# ---------------------------------------------------------------------------
# ZIP extraction (safe — prevents zip-slip)
# ---------------------------------------------------------------------------

def safe_extract_zip(zip_path: Path, dest_dir: Path) -> Path:
    """
    Extract ZIP into dest_dir, guarding against path traversal (zip-slip).

    Returns the path of the top-level directory inside dest_dir.
    If the ZIP has a single root folder, returns that folder.
    Otherwise returns dest_dir itself.

    Restores Unix executable permissions from ZIP metadata where available,
    and auto-detects ELF binaries to mark them executable (ZIP files created
    on Windows or without -X flag lose permission bits).

    Raises ValueError for malicious paths, zipfile.BadZipFile for bad ZIPs.
    """
    dest_dir = dest_dir.resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:
        # Security check: no member may escape dest_dir
        for member in zf.infolist():
            member_path = (dest_dir / member.filename).resolve()
            if not str(member_path).startswith(str(dest_dir) + os.sep):
                raise ValueError(
                    f"Zip-slip detected in member: {member.filename!r}"
                )

        zf.extractall(dest_dir)

        # Restore executable permissions from ZIP external attributes.
        # Also detect ELF binaries and mark them executable even if the
        # ZIP didn't store permission bits (common with Windows-created ZIPs).
        for member in zf.infolist():
            if member.is_dir():
                continue
            extracted = (dest_dir / member.filename).resolve()
            if not extracted.exists():
                continue

            # Check if ZIP stored Unix permissions (external_attr >> 16)
            unix_mode = member.external_attr >> 16
            if unix_mode and (unix_mode & 0o111):
                # ZIP says this file was executable — restore that
                extracted.chmod(extracted.stat().st_mode | 0o111)
                continue

            # No Unix permissions in ZIP — check if it's an ELF binary
            try:
                with open(extracted, "rb") as bf:
                    magic = bf.read(4)
                if magic == b"\x7fELF":
                    extracted.chmod(extracted.stat().st_mode | 0o111)
            except (OSError, IOError):
                pass

    # Try to find a single top-level directory (common for repo ZIPs)
    children = [c for c in dest_dir.iterdir() if not c.name.startswith(".")]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return dest_dir


# ---------------------------------------------------------------------------
# Job runner (runs in a background thread)
# ---------------------------------------------------------------------------

def _stream_process(proc: subprocess.Popen, job: Job) -> None:
    """Read stdout+stderr from proc line-by-line into job log."""
    for line in proc.stdout:
        cleaned = line.rstrip("\n")
        job.append_log(cleaned)
    proc.wait()


def _run_llmscan_phase(job: Job) -> None:
    """
    Run the LLM direct-code scanner as a post-processing step after the main
    raptor scan (scan / agentic / codeql) or as the primary step for llmscan mode.

    Collects any SARIF files already produced in out_dir, passes them to
    raptor_llmscan for merging, and saves merged_report.json into out_dir.
    The function is tolerant of errors — a failure here never changes the job
    status that was already set by the main scan.
    """
    try:
        import glob as _glob

        # If the agentic CLI already ran llmscan and produced a merged report,
        # skip this phase to avoid duplicating work.
        existing_merged = job.out_dir / "merged_report.json"
        if existing_merged.exists():
            job.append_log("[raptor-web] ── LLM Direct-Code Scan ──────────────────")
            job.append_log("[raptor-web] merged_report.json already exists (produced by agentic phase) — skipping duplicate scan")
            # Read the report so counts appear in the job log
            try:
                import json as _json
                with open(existing_merged) as _f:
                    _existing = _json.load(_f)
                _total = _existing.get("total_findings", 0)
                _exploitable = _existing.get("exploitable", 0)
                job.append_log(f"[raptor-web] Existing merged: {_total} total | {_exploitable} exploitable")
                job.append_log("[raptor-web] Merged report: merged_report.json")
            except Exception:
                pass
            job.append_log("[raptor-web] ── LLM Direct-Code Scan complete ─────────")
            return

        job.append_log("[raptor-web] ── LLM Direct-Code Scan ──────────────────")
        job.append_log(f"[raptor-web] Starting LLM direct-code scan of {job.repo_dir.name} ...")

        # Collect SARIF files produced by scan / codeql / agentic phases
        sarif_files = sorted(job.out_dir.rglob("*.sarif"))
        if sarif_files:
            job.append_log(f"[raptor-web] Found {len(sarif_files)} SARIF file(s) to merge")
        else:
            job.append_log("[raptor-web] No SARIF files found — LLM scan will run standalone")

        # Import the llm_scan package (already in the RAPTOR tree)
        sys.path.insert(0, str(RAPTOR_ROOT))
        from packages.llm_scan import LLMScanner, merge_findings
        from packages.llm_scan.merger import load_sarif_findings, normalise_finding
        from core.json import save_json

        # Run LLM scanner in-process — output goes to out_dir/llmscan/
        llmscan_out = job.out_dir / "llmscan"
        llmscan_out.mkdir(parents=True, exist_ok=True)

        scanner = LLMScanner(
            repo_path=job.repo_dir,
            out_dir=llmscan_out,
            max_files=150,           # reasonable cap for web upload jobs
            max_chunks_per_file=15,
        )

        # Redirect scanner log lines into the job log so they appear in the UI
        import logging as _logging
        class _JobLogHandler(_logging.Handler):
            def emit(self, record):
                job.append_log(f"[llmscan] {self.format(record)}")

        _handler = _JobLogHandler()
        _handler.setFormatter(_logging.Formatter("%(message)s"))
        # Attach to the package root so all submodule loggers are captured
        _pkglogger = _logging.getLogger("packages.llm_scan")
        _pkglogger.setLevel(_logging.INFO)  # ensure INFO messages propagate
        _pkglogger.addHandler(_handler)

        try:
            llm_findings = scanner.scan()
        finally:
            _pkglogger.removeHandler(_handler)

        job.append_log(f"[raptor-web] LLM scan: {len(llm_findings)} raw finding(s)")

        # Load and merge SARIF findings
        sarif_findings = []
        for sf in sarif_files:
            loaded = load_sarif_findings(sf)
            sarif_findings.extend(loaded)

        if sarif_findings:
            job.append_log(f"[raptor-web] Merging {len(llm_findings)} LLM + {len(sarif_findings)} SARIF findings ...")

        merged = merge_findings(
            llm_findings=llm_findings,
            sarif_findings=sarif_findings,
        )

        # Count breakdown
        exploitable = sum(1 for f in merged if f.get("is_exploitable"))
        llm_only    = sum(1 for f in merged if (f.get("sources") or []) == ["llmscan"])
        confirmed   = sum(1 for f in merged if "llmscan" in (f.get("sources") or [])
                         and any(t != "llmscan" for t in (f.get("sources") or [])))

        job.append_log(
            f"[raptor-web] Merged: {len(merged)} total | "
            f"{exploitable} exploitable | "
            f"{confirmed} confirmed by both | "
            f"{llm_only} LLM-only"
        )

        # Build and save the merged report (compatible with web results page)
        from collections import Counter
        sev_counts  = Counter(f.get("severity", "unknown") for f in merged)
        tool_counts: Counter = Counter()
        for f in merged:
            for t in (f.get("sources") or [f.get("tool", "unknown")]):
                tool_counts[t] += 1

        report = {
            "tool":             "llmscan+merge",
            "repo":             str(job.repo_dir),
            "mode":             job.mode,
            "total_findings":   len(merged),
            "exploitable":      exploitable,
            "exploits_generated": sum(1 for f in merged if f.get("exploit_code")),
            "patches_generated":  sum(1 for f in merged if f.get("patch_code")),
            "severity_breakdown": dict(sev_counts),
            "source_breakdown": {
                "llm_only":    llm_only,
                "sarif_only":  len(merged) - llm_only - confirmed,
                "confirmed_both": confirmed,
            },
            "tool_breakdown":   dict(tool_counts),
            "results":          merged,
        }

        merged_report_path = job.out_dir / "merged_report.json"
        save_json(merged_report_path, report)
        job.append_log(f"[raptor-web] Merged report: {merged_report_path.name}")
        job.append_log("[raptor-web] ── LLM Direct-Code Scan complete ─────────")

    except ImportError as exc:
        job.append_log(f"[raptor-web] LLM scan skipped (import error): {exc}")
    except Exception as exc:
        # Non-fatal: log the error but don't change job status
        job.append_log(f"[raptor-web] LLM scan phase error (non-fatal): {exc}")
        log.warning("LLM scan phase failed for job %s: %s", job.job_id, exc, exc_info=True)


def run_job(job: Job) -> None:
    """
    Background thread: extract ZIP, build raptor command, run it.
    All subprocess args are built as a list (no shell=True).
    """
    job.status = "running"
    job.started_at = time.time()
    _persist_job(job)
    job.append_log(f"[raptor-web] Job {job.job_id} started at {datetime.datetime.now().isoformat()}")
    job.append_log(f"[raptor-web] Mode: {job.mode}")

    try:
        # ── Step 1: extract ZIP ──────────────────────────────────
        job.append_log(f"[raptor-web] Extracting {job.upload_path.name} ...")
        job.repo_dir = safe_extract_zip(job.upload_path, job.work_dir / "repo")
        job.append_log(f"[raptor-web] Extracted to: {job.repo_dir.name}")

        # ── Step 2: ensure exploits/ and patches/ dirs exist ────
        (job.out_dir / "exploits").mkdir(parents=True, exist_ok=True)
        (job.out_dir / "patches").mkdir(parents=True, exist_ok=True)

        # ── Step 3: build raptor.py command ─────────────────────
        raptor_script = RAPTOR_ROOT / "raptor.py"
        cmd = [sys.executable, str(raptor_script), job.mode]

        if job.mode in {"scan", "agentic", "codeql", "llmscan"}:
            cmd += ["--repo", str(job.repo_dir)]

        elif job.mode == "webapp":
            cmd += ["--repo", str(job.repo_dir)]
            # Pass through toggle flags from extra_args
            job.append_log(f"[raptor-web] Web App mode: {job.repo_dir.name}")

        elif job.mode == "binary":
            # Binary mode: check for --binary in extra_args
            binary_arg = _find_extra_arg(job.extra_args, "--binary")
            if binary_arg:
                repo_root = job.repo_dir.resolve()
                binary_abs = (repo_root / binary_arg).resolve()
                if not str(binary_abs).startswith(str(repo_root)):
                    raise ValueError(f"Binary path escapes repo root: {binary_arg!r}")
                if not binary_abs.exists():
                    raise FileNotFoundError(f"Binary not found: {binary_arg}")
                if not os.access(binary_abs, os.X_OK):
                    binary_abs.chmod(binary_abs.stat().st_mode | 0o111)
                    job.append_log(f"[raptor-web] Set executable bit on {binary_arg}")
                job.extra_args = _replace_extra_arg(
                    job.extra_args, "--binary", str(binary_abs)
                )
            else:
                cmd += ["--repo", str(job.repo_dir)]
            job.append_log(f"[raptor-web] Binary mode: {job.repo_dir.name}")

        elif job.mode == "fuzz":
            # Fuzz mode supports two sub-modes:
            # 1. --binary <relative-path>: pre-compiled binary in the ZIP
            # 2. --repo (default): source code in the ZIP, will be instrumented
            binary_arg = _find_extra_arg(job.extra_args, "--binary")
            if binary_arg:
                # Pre-compiled binary mode — resolve path within extracted repo
                repo_root = job.repo_dir.resolve()
                binary_abs = (repo_root / binary_arg).resolve()
                if not str(binary_abs).startswith(str(repo_root)):
                    raise ValueError(
                        f"Binary path escapes repo root: {binary_arg!r}"
                    )
                if not binary_abs.exists():
                    raise FileNotFoundError(
                        f"Binary not found in extracted repo: {binary_arg}"
                    )
                # Ensure the binary is executable — ZIP extraction often
                # strips permission bits, especially from Windows-created ZIPs.
                if not os.access(binary_abs, os.X_OK):
                    binary_abs.chmod(binary_abs.stat().st_mode | 0o111)
                    job.append_log(f"[raptor-web] Set executable bit on {binary_arg}")
                # Replace user --binary with absolute (within repo) path
                job.extra_args = _replace_extra_arg(
                    job.extra_args, "--binary", str(binary_abs)
                )
            else:
                # Source instrumentation mode (default) — pass --repo so
                # raptor_fuzzing.py will detect the build system, compile
                # with afl-clang-fast, and find the resulting binary.
                cmd += ["--repo", str(job.repo_dir)]
                job.append_log(f"[raptor-web] Fuzz source mode: will instrument {job.repo_dir.name} with AFL++")

        # Attach output dir (all modes now accept --out)
        cmd += ["--out", str(job.out_dir)]

        # Attach any extra user args
        cmd += job.extra_args

        job.append_log(f"[raptor-web] Command: {' '.join(cmd)}")

        # ── Step 4: run raptor ───────────────────────────────────
        env = os.environ.copy()
        env["RAPTOR_OUT_DIR"] = str(job.out_dir)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(job.repo_dir),
            env=env,
            start_new_session=True,   # creates a new process group so kill()
        )                              # can terminate all child processes (afl, semgrep, etc.)

        # Store handle so /api/jobs/<id>/kill can terminate it
        with job._lock:
            job._proc = proc

        _stream_process(proc, job)
        job.return_code = proc.returncode

        with job._lock:
            job._proc = None  # process finished, clear handle

        if proc.returncode == 0:
            # Don't set status to "done" yet — keep "running" so the UI
            # continues streaming log lines during the llmscan phase below.
            _intended_status = "done"
            job.append_log(f"[raptor-web] ✓ Main scan completed (exit 0)")
        elif job.status == "killed":
            _intended_status = "killed"  # already set by kill()
        else:
            _intended_status = "error"
            job.append_log(
                f"[raptor-web] ✗ raptor exited with code {proc.returncode}"
            )

        # ── Step 5: LLM direct-code scan (scan/agentic/codeql/llmscan modes) ──
        # Runs while status is still "running" so the web client keeps polling
        # and the user sees llmscan log lines live. Final status is set after.
        if job.mode in {"scan", "agentic", "codeql", "llmscan"} and _intended_status != "killed":
            _run_llmscan_phase(job)

        # Now set the final status — this is when the JS poll will trigger reload.
        if job.status != "killed":
            job.status = _intended_status
            if _intended_status == "done":
                job.append_log(f"[raptor-web] ✓ All phases complete")
        _persist_job(job)  # persist final status

    except (ValueError, FileNotFoundError) as exc:
        job.status = "error"
        job.append_log(f"[raptor-web] ✗ Setup error: {exc}")
        log.error("Job %s setup error: %s", job.job_id, exc)
        _persist_job(job)

    except Exception as exc:
        job.status = "error"
        job.append_log(f"[raptor-web] ✗ Unexpected error: {exc}")
        log.exception("Job %s unexpected error", job.job_id)
        _persist_job(job)

    finally:
        job.finished_at = time.time()
        job.append_log(
            f"[raptor-web] Finished at {datetime.datetime.now().isoformat()} "
            f"(duration: {job.duration:.1f}s)"
        )


def _find_extra_arg(args: List[str], flag: str) -> Optional[str]:
    """Return the value for a flag in an args list, or None."""
    for i, arg in enumerate(args):
        if arg == flag and i + 1 < len(args):
            return args[i + 1]
    return None


def _replace_extra_arg(
    args: List[str], flag: str, new_value: str
) -> List[str]:
    """Return a new args list with the value for flag replaced."""
    out = list(args)
    for i, arg in enumerate(out):
        if arg == flag and i + 1 < len(out):
            out[i + 1] = new_value
            return out
    return out


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    """Upload form."""
    return render_template_string(INDEX_HTML, jobs=list(JOBS.values()))


@app.route("/upload", methods=["POST"])
def upload():
    """Accept ZIP upload + mode, start job, redirect to results page."""
    # Validate mode
    mode = request.form.get("mode", "scan").strip().lower()
    if mode not in ALLOWED_MODES:
        return jsonify({"error": f"Invalid mode: {mode}"}), 400

    # Validate file
    if "zipfile" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded = request.files["zipfile"]
    if not uploaded.filename:
        return jsonify({"error": "Empty filename"}), 400

    # Only allow ZIP files
    fname = uploaded.filename
    if not (fname.lower().endswith(".zip")):
        return jsonify({"error": "Only .zip files are accepted"}), 400

    # Parse optional extra args (e.g. --binary mybin --duration 60)
    extra_raw = request.form.get("extra_args", "").strip()
    try:
        extra_args = _parse_extra_args(extra_raw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # Create job
    job_id = str(uuid.uuid4())[:8]
    work_dir = WORK_ROOT / job_id
    work_dir.mkdir(parents=True, exist_ok=True)

    # Save ZIP safely
    zip_dest = work_dir / "upload.zip"
    uploaded.save(str(zip_dest))

    job = Job(
        job_id=job_id,
        mode=mode,
        upload_path=zip_dest,
        work_dir=work_dir,
        extra_args=extra_args,
    )
    JOBS[job_id] = job
    _persist_job(job)  # persist immediately so it survives even a crash before thread starts

    # Start background thread
    t = threading.Thread(target=run_job, args=(job,), daemon=True)
    t.start()

    return redirect(url_for("results", job_id=job_id))


@app.route("/results/<job_id>")
def results(job_id: str):
    """Results page — auto-refreshes while job is running."""
    job = JOBS.get(job_id)
    if not job:
        return f"Job {job_id!r} not found.", 404

    results_data = job.collect_results()
    summary = job.build_summary()
    log_html = _colorize_log_html(job.get_log())

    return render_template(
        "results.html",
        job_id=job_id,
        mode=job.mode,
        status=job.status,
        summary=summary,
        findings=results_data.get("findings", []),
        exploits=results_data.get("exploits", []),
        patches=results_data.get("patches", []),
        cross_groups=results_data.get("cross_groups", []),
        raw_results=results_data.get("_raw_json"),
        log_output=log_html,
        generated_at=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/api/jobs")
def api_jobs():
    """JSON list of all jobs."""
    return jsonify([
        {
            "job_id": j.job_id,
            "mode": j.mode,
            "status": j.status,
            "duration": j.duration,
        }
        for j in JOBS.values()
    ])


@app.route("/api/jobs/<job_id>")
def api_job(job_id: str):
    """JSON status + log for a single job."""
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "job_id": job.job_id,
        "mode": job.mode,
        "status": job.status,
        "return_code": job.return_code,
        "duration": job.duration,
        "log": job.get_log(),
        "summary": job.build_summary(),
    })


@app.route("/api/jobs/<job_id>/log")
def api_job_log(job_id: str):
    """Plain-text log for a job (useful for polling)."""
    job = JOBS.get(job_id)
    if not job:
        return "not found", 404
    return job.get_log(), 200, {"Content-Type": "text/plain"}


@app.route("/api/jobs/<job_id>/kill", methods=["POST"])
def api_job_kill(job_id: str):
    """Terminate a running job. POST only."""
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    if job.status not in ("pending", "running"):
        return jsonify({"error": f"Job is already {job.status}"}), 409
    killed = job.kill()
    if killed:
        log.info("Job %s killed by user request", job_id)
        return jsonify({"status": "killed", "job_id": job_id})
    return jsonify({"error": "Process not running or could not be killed"}), 500


# ---------------------------------------------------------------------------
# Report parsing helpers
# ---------------------------------------------------------------------------

def _normalise_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalise a finding dict to a consistent shape regardless of which
    report file it came from (orchestrated / agentic / autonomous).

    All rendering code in results.html depends on these field names.
    """
    out = dict(f)

    # Severity: unify level/severity_assessment -> severity
    if "severity" not in out:
        out["severity"] = (
            out.get("severity_assessment")
            or out.get("level")
            or "unknown"
        )

    # File path: unify path/file_path
    if "file_path" not in out:
        out["file_path"] = out.get("path") or out.get("file") or ""

    # Ruling verdict display label
    ruling = out.get("ruling") or ""
    if not ruling:
        if out.get("is_exploitable"):
            ruling = "exploitable"
        elif out.get("is_true_positive") is False:
            ruling = "false_positive"
        elif out.get("is_true_positive"):
            ruling = "confirmed"
    out["ruling"] = ruling

    return out


def _parse_orchestrated_findings(
    orch: Dict[str, Any],
    out_dir: Path,
) -> List[Dict[str, Any]]:
    """
    Parse findings from orchestrated_report.json.

    The report has a top-level "results" list. Each result contains the
    original scanner fields PLUS all LLM-generated fields merged in by
    packages/llm_analysis/orchestrator.py::_merge_results().

    Key fields rendered by results.html:
      rule_id, file_path, start_line, severity / severity_assessment,
      is_true_positive, is_exploitable, exploitability_score,
      ruling, confidence, reasoning, attack_scenario, impact,
      prerequisites, cvss_vector, cvss_score_estimate,
      vuln_type, cwe_id, dataflow_summary, remediation,
      exploit_code (has_exploit=True), patch_code (has_patch=True),
      false_positive_reason, message, tool
    """
    raw_findings = orch.get("results") or []
    if not isinstance(raw_findings, list):
        return []

    parsed = []
    for f in raw_findings:
        if not isinstance(f, dict):
            continue

        n = _normalise_finding(f)

        # Attach exploit code from disk if not inline
        if n.get("has_exploit") and not n.get("exploit_code"):
            fid = n.get("finding_id") or n.get("rule_id", "")
            for ext in (".cpp", ".py", ".c", ".sh"):
                candidate = out_dir / "exploits" / f"{fid}_exploit{ext}"
                if candidate.exists():
                    n["exploit_code"] = candidate.read_text(errors="replace")
                    break

        # Attach patch from disk if not inline
        if n.get("has_patch") and not n.get("patch_code"):
            fid = n.get("finding_id") or n.get("rule_id", "")
            candidate = out_dir / "patches" / f"{fid}_patch.md"
            if candidate.exists():
                n["patch_code"] = candidate.read_text(errors="replace")

        parsed.append(n)

    return parsed


def _parse_cross_groups(
    orch: Dict[str, Any],
    out_dir: Path,
) -> List[Dict[str, Any]]:
    """
    Parse cross_finding_groups from orchestrated_report.json.

    Each group has: group_id, criterion, criterion_value, finding_ids
    Optional group_analyses dict (keyed by group_id) may add LLM analysis text.
    """
    raw_groups = orch.get("cross_finding_groups") or []
    if not isinstance(raw_groups, list):
        return []

    group_analyses = orch.get("group_analyses") or {}

    result = []
    for g in raw_groups:
        if not isinstance(g, dict):
            continue
        gid = g.get("group_id", "")
        entry = {
            "group_id": gid,
            "criterion": g.get("criterion", ""),
            "criterion_value": g.get("criterion_value", ""),
            "finding_ids": g.get("finding_ids", []),
        }
        # Attach LLM group analysis if available.
        # group_analyses entries come from GroupAnalysisTask which returns free-form
        # text stored under the "content" key (see dispatch.py result={"content": ...}).
        if gid and gid in group_analyses:
            ga = group_analyses[gid]
            if isinstance(ga, dict):
                # "content" is the primary key from GroupAnalysisTask free-form output
                entry["analysis"] = (
                    ga.get("content")
                    or ga.get("analysis")
                    or ga.get("reasoning")
                    or ""
                )
            elif isinstance(ga, str):
                entry["analysis"] = ga
        result.append(entry)

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAFE_ARG_RE = re.compile(r'^[\w./:@=,&?+%#-]+$')


def _parse_extra_args(raw: str) -> List[str]:
    """
    Parse extra CLI args from a string, returning a safe list.
    Allows only alphanumeric, dots, slashes, colons, @, =, comma, dash.
    Raises ValueError on suspicious input.
    """
    if not raw:
        return []

    tokens = raw.split()
    result = []

    for token in tokens:
        if not _SAFE_ARG_RE.match(token):
            raise ValueError(
                f"Extra arg contains unsafe characters: {token!r}. "
                f"Only alphanumeric, './:@=,-' are allowed."
            )
        result.append(token)

    return result


_LOG_HTML_ESCAPES = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})


def _colorize_log_html(log_text: str) -> str:
    """Wrap log lines in spans for CSS colorization."""
    lines = log_text.split("\n")
    parts = []
    for line in lines:
        escaped = line.translate(_LOG_HTML_ESCAPES)
        if "ERROR" in line or "✗" in line or "FAIL" in line.upper():
            parts.append(f'<span class="log-error">{escaped}</span>')
        elif "WARN" in line or "warning" in line.lower():
            parts.append(f'<span class="log-warn">{escaped}</span>')
        elif "✓" in line or "SUCCESS" in line or "DONE" in line:
            parts.append(f'<span class="log-ok">{escaped}</span>')
        elif "DEBUG" in line:
            parts.append(f'<span class="log-debug">{escaped}</span>')
        else:
            parts.append(f'<span class="log-info">{escaped}</span>')
    return "\n".join(parts)


def render_template_string(tmpl: str, **ctx) -> str:
    """Simple {var} template renderer for the index page."""
    from flask import render_template_string as _rts
    return _rts(tmpl, **ctx)


# ---------------------------------------------------------------------------
# Index page HTML (self-contained, no external deps)
# ---------------------------------------------------------------------------

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>RAPTOR — Security Analysis</title>
  <style>
    :root {
      --bg:#0d1117; --surface:#161b22; --border:#30363d;
      --accent:#58a6ff; --accent2:#d29922; --green:#3fb950; --red:#f85149;
      --text:#e6edf3; --muted:#8b949e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; }
    header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; }
    header h1 { color: var(--accent); font-size: 22px; letter-spacing: 2px; }
    header p { color: var(--muted); font-size: 12px; margin-top: 4px; }
    main { max-width: 760px; margin: 32px auto; padding: 0 24px; }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 24px;
      margin-bottom: 24px;
    }
    .card h2 { font-size: 16px; margin-bottom: 16px; }

    label { display: block; margin-bottom: 6px; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }

    input[type=file], input[type=text], input[type=url], select, textarea {
      width: 100%; background: #0d1117; border: 1px solid var(--border);
      border-radius: 4px; color: var(--text); padding: 8px 10px;
      font-size: 13px; margin-bottom: 16px; font-family: inherit;
    }

    /* Mode cards — just 2 now */
    .mode-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
    .mode-card {
      border: 2px solid var(--border); border-radius: 6px;
      padding: 18px; cursor: pointer; transition: all 0.2s;
      position: relative; overflow: hidden;
    }
    .mode-card:hover { border-color: var(--muted); }
    .mode-card.selected { border-color: var(--accent); background: rgba(88,166,255,0.05); }
    .mode-card input { display: none; }
    .mode-card .icon { font-size: 24px; margin-bottom: 8px; }
    .mode-card .title { font-weight: 700; font-size: 15px; letter-spacing: 0.5px; }
    .mode-card .desc { color: var(--muted); font-size: 12px; margin-top: 4px; line-height: 1.4; }

    /* Toggle switches */
    .toggles { display: grid; grid-template-columns: 1fr 1fr; gap: 10px 16px; margin-bottom: 16px; }
    .toggle-row {
      display: flex; align-items: center; justify-content: space-between;
      padding: 10px 12px; background: #0d1117; border: 1px solid var(--border);
      border-radius: 4px; font-size: 13px;
    }
    .toggle-row.binary-only { display: none; }
    .toggle-row.hidden { display: none; }
    body.mode-binary .toggle-row.binary-only { display: flex; }

    .toggle-label { display: flex; align-items: center; gap: 8px; text-transform: none; letter-spacing: 0; color: var(--text); font-size: 13px; margin: 0; }
    .toggle-label .tool-name { font-weight: 600; }

    .switch { position: relative; width: 38px; height: 20px; flex-shrink: 0; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0;
      background: #30363d; border-radius: 20px; transition: 0.2s;
    }
    .slider::before {
      position: absolute; content: ""; height: 14px; width: 14px;
      left: 3px; bottom: 3px; background: #8b949e;
      border-radius: 50%; transition: 0.2s;
    }
    .switch input:checked + .slider { background: var(--accent); }
    .switch input:checked + .slider::before { transform: translateX(18px); background: #0d1117; }

    /* URL input rows — only show for relevant modes */
    .url-row { margin-bottom: 12px; }
    .url-row.hidden { display: none; }
    .url-row label { display: flex; align-items: center; gap: 8px; justify-content: space-between; margin-bottom: 6px; }
    .url-row label .url-title { display: flex; align-items: center; gap: 6px; }
    .url-row input[type=url] { margin-bottom: 0; }

    body.mode-webapp .binary-url { display: none; }
    body.mode-binary .webapp-url { display: none; }

    .btn {
      display: inline-block; background: var(--accent); color: #0d1117;
      border: none; border-radius: 4px; padding: 12px 24px;
      font-size: 14px; font-weight: 700; cursor: pointer; width: 100%;
      letter-spacing: 0.5px;
    }
    .btn:hover { opacity: 0.92; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }

    .hint { color: var(--muted); font-size: 11px; margin-top: 8px; line-height: 1.5; }

    /* Pipeline preview */
    .pipeline-preview {
      display: flex; gap: 4px; align-items: center; margin: 16px 0;
      padding: 14px; background: #0d1117; border: 1px solid var(--border);
      border-radius: 4px; font-size: 11px; color: var(--muted);
      overflow-x: auto; white-space: nowrap;
    }
    .pipeline-step {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 10px; border-radius: 12px; background: #161b22;
      border: 1px solid var(--border);
    }
    .pipeline-step::before {
      content: "○"; color: var(--muted);
    }
    .pipeline-arrow { color: var(--border); font-size: 14px; }

    /* Jobs table */
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px 10px; border-bottom: 1px solid var(--border); text-align: left; font-size: 13px; }
    th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
    .badge-done    { background: #1a3a2a; color: #3fb950; }
    .badge-running { background: #1c3a5a; color: #58a6ff; }
    .badge-error   { background: #3a1a1a; color: #f85149; }
    .badge-pending { background: #2a2a1a; color: #d29922; }
    .badge-killed  { background: #3a2a3a; color: #bc8cff; }
  </style>
</head>
<body class="mode-webapp">

<header>
  <h1>RAPTOR</h1>
  <p>Automated Security Analysis — v2</p>
</header>

<main>
  <div class="card">
    <h2>🚀 New Analysis</h2>

    <form action="/upload" method="post" enctype="multipart/form-data" id="scanForm">

      <label>Repository ZIP</label>
      <input type="file" name="zipfile" accept=".zip" required>
      <div class="hint" style="margin-top:-10px;margin-bottom:16px">Upload a ZIP of the source repository or binary (max {{ max_mb }} MB)</div>

      <label>Analysis Mode</label>
      <div class="mode-grid">
        <label class="mode-card selected" data-mode="webapp">
          <input type="radio" name="mode" value="webapp" checked>
          <div class="icon">🌐</div>
          <div class="title">Web App</div>
          <div class="desc">SQL injection, XSS, CSRF, auth, path traversal, SSRF, secrets</div>
        </label>
        <label class="mode-card" data-mode="binary">
          <input type="radio" name="mode" value="binary">
          <div class="icon">🔧</div>
          <div class="title">Binary</div>
          <div class="desc">Buffer overflow, memory corruption, AFL++ fuzzing, crashes</div>
        </label>
      </div>

      <label>Discovery Tools</label>
      <div class="toggles">
        <div class="toggle-row">
          <label class="toggle-label"><span class="tool-name">Semgrep</span></label>
          <label class="switch"><input type="checkbox" name="semgrep" checked><span class="slider"></span></label>
        </div>
        <div class="toggle-row">
          <label class="toggle-label"><span class="tool-name">CodeQL</span></label>
          <label class="switch"><input type="checkbox" name="codeql"><span class="slider"></span></label>
        </div>
        <div class="toggle-row">
          <label class="toggle-label"><span class="tool-name">TruffleHog</span></label>
          <label class="switch"><input type="checkbox" name="trufflehog" checked><span class="slider"></span></label>
        </div>
        <div class="toggle-row">
          <label class="toggle-label"><span class="tool-name">LLMScan</span></label>
          <label class="switch"><input type="checkbox" name="llmscan" checked><span class="slider"></span></label>
        </div>
        <div class="toggle-row binary-only">
          <label class="toggle-label"><span class="tool-name">Fuzzing (AFL++)</span></label>
          <label class="switch"><input type="checkbox" name="fuzz"><span class="slider"></span></label>
        </div>
        <div class="toggle-row binary-only">
          <label class="toggle-label"><span class="tool-name">Firmware Emulation (QEMU)</span></label>
          <label class="switch"><input type="checkbox" name="emulate"><span class="slider"></span></label>
        </div>
      </div>

      <div class="url-row webapp-url">
        <label>
          <span class="url-title">🎯 App URL (optional)</span>
          <label class="switch"><input type="checkbox" id="toggle-app-url"><span class="slider"></span></label>
        </label>
        <input type="url" name="app_url" id="app-url-input" placeholder="https://example.com" disabled>
        <div class="hint">Test discovered findings against this URL with nmap, gobuster, sqlmap</div>
      </div>

      <div class="url-row webapp-url">
        <label>
          <span class="url-title">🔀 Proxy URL (optional)</span>
          <label class="switch"><input type="checkbox" id="toggle-proxy-url"><span class="slider"></span></label>
        </label>
        <input type="url" name="proxy_url" id="proxy-url-input" placeholder="http://127.0.0.1:8080" disabled>
        <div class="hint">Route all outbound requests (Burp Suite, ZAP, etc.)</div>
      </div>

      <div class="url-row binary-url">
        <label>
          <span class="url-title">🐛 Bug Track URL (optional)</span>
          <label class="switch"><input type="checkbox" id="toggle-bug-url"><span class="slider"></span></label>
        </label>
        <input type="url" name="bug_track_url" id="bug-url-input" placeholder="https://bugs.example.com/issue/1234" disabled>
        <div class="hint">Extract crash or PoC from this URL and analyse with gdb</div>
      </div>

      <label>Pipeline</label>
      <div class="pipeline-preview">
        <span class="pipeline-step">Discovery</span>
        <span class="pipeline-arrow">→</span>
        <span class="pipeline-step">Analysis</span>
        <span class="pipeline-arrow">→</span>
        <span class="pipeline-step">Exploitation</span>
        <span class="pipeline-arrow">→</span>
        <span class="pipeline-step">Patching</span>
        <span class="pipeline-arrow">→</span>
        <span class="pipeline-step">Presenting</span>
      </div>

      <button type="submit" class="btn" id="submitBtn">▶ Start Analysis</button>
    </form>
  </div>

  {% if jobs %}
  <div class="card">
    <h2>📋 Recent Jobs</h2>
    <table>
      <thead>
        <tr><th>Job ID</th><th>Mode</th><th>Status</th><th>Duration</th><th></th></tr>
      </thead>
      <tbody>
        {% for job in jobs | reverse %}
        <tr>
          <td><code>{{ job.job_id }}</code></td>
          <td>{{ job.mode }}</td>
          <td><span class="badge badge-{{ job.status }}">{{ job.status }}</span></td>
          <td>{% if job.duration %}{{ "%.0f"|format(job.duration) }}s{% else %}—{% endif %}</td>
          <td><a href="/results/{{ job.job_id }}">View →</a></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
</main>

<script>
const MAX_MB = {{ max_mb }};

// Mode selection — switches body class for CSS-driven show/hide of binary-only/webapp-only controls
document.querySelectorAll('.mode-card').forEach(card => {
  card.addEventListener('click', () => {
    document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('selected'));
    card.classList.add('selected');
    const mode = card.dataset.mode;
    card.querySelector('input[type=radio]').checked = true;
    document.body.className = 'mode-' + mode;
  });
});

// URL input toggles (enable/disable based on switch)
['app-url', 'proxy-url', 'bug-url'].forEach(id => {
  const toggle = document.getElementById('toggle-' + id);
  const input = document.getElementById(id + '-input');
  if (toggle && input) {
    toggle.addEventListener('change', () => {
      input.disabled = !toggle.checked;
      if (!toggle.checked) input.value = '';
    });
  }
});

// File size guard
document.querySelector('input[type=file]').addEventListener('change', function() {
  const file = this.files[0];
  if (file && file.size > MAX_MB * 1024 * 1024) {
    alert('File too large (' + (file.size / 1024 / 1024).toFixed(1) + ' MB). Max: ' + MAX_MB + ' MB.');
    this.value = '';
  }
});

// Build extra_args from toggles and submit
document.getElementById('scanForm').addEventListener('submit', function(e) {
  e.preventDefault();

  const form = this;
  const mode = form.querySelector('input[name=mode]:checked').value;
  const extraArgs = [];

  // Tool toggles → --no-<tool> flags for disabled tools
  const tools = ['semgrep', 'codeql', 'trufflehog', 'llmscan'];
  if (mode === 'binary') tools.push('fuzz');
  tools.forEach(tool => {
    const cb = form.querySelector(`input[name="${tool}"]`);
    if (cb && !cb.checked) {
      extraArgs.push('--no-' + tool);
    } else if (cb && cb.checked && (tool === 'codeql' || tool === 'fuzz')) {
      // These are opt-in (default off in argparse); explicitly enable
      extraArgs.push('--' + tool);
    }
  });

  // URLs (only if toggle is on AND value is non-empty)
  const appUrl = form.querySelector('#app-url-input');
  if (appUrl && !appUrl.disabled && appUrl.value.trim()) {
    extraArgs.push('--app-url', appUrl.value.trim());
  }
  const proxyUrl = form.querySelector('#proxy-url-input');
  if (proxyUrl && !proxyUrl.disabled && proxyUrl.value.trim()) {
    extraArgs.push('--proxy-url', proxyUrl.value.trim());
  }
  const bugUrl = form.querySelector('#bug-url-input');
  if (bugUrl && !bugUrl.disabled && bugUrl.value.trim()) {
    extraArgs.push('--bug-track-url', bugUrl.value.trim());
  }

  // Binary emulation flag
  const emulate = form.querySelector('input[name=emulate]');
  if (mode === 'binary' && emulate && emulate.checked) {
    extraArgs.push('--emulate');
  }

  // Inject as a hidden textarea field named 'extra_args'
  let hidden = form.querySelector('textarea[name=extra_args]');
  if (!hidden) {
    hidden = document.createElement('textarea');
    hidden.name = 'extra_args';
    hidden.style.display = 'none';
    form.appendChild(hidden);
  }
  hidden.value = extraArgs.join(' ');

  // Disable button to prevent double-submit
  const btn = document.getElementById('submitBtn');
  btn.disabled = true;
  btn.innerText = '⏳ Uploading...';

  // Submit
  form.submit();
});
</script>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def main() -> None:
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    _load_persisted_jobs()  # restore jobs from previous session

    parser = argparse.ArgumentParser(description="RAPTOR Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  RAPTOR Web Server")
    print(f"  http://{args.host}:{args.port}")
    print(f"  Raptor root: {RAPTOR_ROOT}")
    print(f"  Work dir:    {WORK_ROOT}")
    print(f"  Max upload:  {MAX_UPLOAD_MB} MB")
    print(f"{'='*60}\n")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
