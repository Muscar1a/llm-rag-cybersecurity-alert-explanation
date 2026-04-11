#!/usr/bin/env python3
"""
Cross-platform DVC pipeline runner.
Equivalent to dvc_run_pipeline.sh — works on Windows, Mac, and Linux.
Safe to run multiple times (idempotent).
Usage: python scripts/run_pipeline.py
"""

import subprocess
import sys


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd: list[str], step: str = "") -> int:
    """Run a command, stream output live, return exit code."""
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, text=True)
    return result.returncode


def run_required(cmd: list[str], step: str = "") -> None:
    """Run a command that MUST succeed; exit on failure."""
    code = run(cmd, step)
    if code != 0:
        print(f"\n❌ Command failed (exit code {code})")
        if step:
            print(f"   Failed at: {step}")
        sys.exit(code)


def git_commit_if_changed(message: str, step: str = "") -> None:
    """
    Commit only when there are staged changes.
    Skips silently if nothing is staged — safe for repeated runs.
    """
    # Check if anything is actually staged
    staged = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        text=True,
    )
    if staged.returncode == 0:
        # Exit code 0 means no staged changes
        print(f"  ⏭  Nothing to commit, skipping: {message!r}")
        return
    run_required(["git", "commit", "-m", message], step=step)


def clear_dvc_locks() -> None:
    """
    Remove stale DVC lock files left by previously killed processes.
    DVC auto-cleans these, but doing it explicitly avoids the warnings.
    """
    import glob
    import os

    lock_patterns = [
        ".dvc/tmp/rwlock",
        ".dvc/tmp/*.lock",
    ]
    removed = []
    for pattern in lock_patterns:
        for path in glob.glob(pattern):
            try:
                os.remove(path)
                removed.append(path)
            except OSError:
                pass  # already gone or in use — DVC will handle it

    if removed:
        print(f"  🧹 Removed stale lock files: {', '.join(removed)}")


def log(msg: str) -> None:
    """Print a colored step header (green)."""
    green = "\033[32m"
    reset = "\033[0m"
    print(f"\n{green}{msg}{reset}")


# ── Main pipeline ─────────────────────────────────────────────────────────────

def main():
    # Clean up stale locks from any previously interrupted run
    clear_dvc_locks()

    # ── Step 1: Track raw data ────────────────────────────────────────────
    log("Step 1: Add raw data")
    # `dvc add` exits 0 even when data hasn't changed (just prints "skipping")
    run_required(["dvc", "add", "data/raw/CVE/"],        step="dvc add CVE")
    run_required(["dvc", "add", "data/raw/MITRE/"],      step="dvc add MITRE")
    run_required(["dvc", "add", "data/raw/CICIDS2017/"], step="dvc add CICIDS2017")

    run_required(
        ["git", "add",
         "data/raw/CVE.dvc",
         "data/raw/MITRE.dvc",
         "data/raw/CICIDS2017.dvc"],
        step="git add .dvc files",
    )
    # Skip commit if .dvc files haven't changed (idempotent)
    git_commit_if_changed(
        "Track raw datasets with DVC",
        step="git commit raw data",
    )

    # ── Step 2: Push raw data to minio-raw ──────────────────────────────────
    log("Step 2: Push raw data to minio-raw")
    # Push only the .dvc-tracked raw files to the raw bucket
    run_required(
        ["dvc", "push",
         "data/raw/CVE.dvc",
         "data/raw/MITRE.dvc",
         "data/raw/CICIDS2017.dvc",
         "--remote", "minio-raw"],
        step="dvc push raw",
    )

    # ── Step 3: Run DVC pipeline ──────────────────────────────────────────
    log("Step 3: Run DVC pipeline")
    # `dvc repro` skips stages that are already up-to-date — safe to re-run
    run_required(["dvc", "repro"], step="dvc repro")

    # ── Step 4: Push processed data to minio-processed ───────────────────── 
    log("Step 4: Push processed data to minio-processed")
    # dvc.yaml outputs are annotated with `remote: minio-processed`,
    # so a plain `dvc push` routes them to the correct bucket automatically.
    run_required(["dvc", "push", "--remote", "minio-processed"], step="dvc push processed")

    run_required(["git", "add", "dvc.lock"], step="git add dvc.lock")
    # Skip commit if dvc.lock hasn't changed (idempotent)
    git_commit_if_changed(
        "chore: Update dvc.lock after running pipeline",
        step="git commit dvc.lock",
    )

    print("\n✅ Pipeline completed successfully!")


if __name__ == "__main__":
    main()
