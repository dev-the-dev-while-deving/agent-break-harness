"""FastAPI dashboard + black-box POST /run."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from harness.agent import get_target
from harness.runner import list_reports, load_report, run_suite

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Agent Break Harness", version="0.1.0")


class RunBody(BaseModel):
    messages: list[dict[str, Any]]
    tools: list[Any] | None = None
    target: str = "victim"


class SuiteBody(BaseModel):
    target: str = Field(default="both")


@app.get("/")
def dashboard():
    return FileResponse(STATIC / "index.html")


@app.post("/run")
def black_box_run(body: RunBody):
    """Black-box target contract: {messages, tools?} → {messages, tool_calls, final}."""
    try:
        agent = get_target(body.target)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return agent.run(body.messages, body.tools)


@app.post("/api/run-suite")
def api_run_suite(body: SuiteBody | None = None):
    target = (body.target if body else "both") or "both"
    if target not in {"victim", "hardened", "both"}:
        raise HTTPException(400, "target must be victim, hardened, or both")
    reports = run_suite(target=target)
    return {
        "ok": True,
        "count": len(reports),
        "fails": sum(1 for r in reports if r["verdict"] == "fail"),
        "reports": reports,
    }


@app.get("/api/reports")
def api_list_reports():
    reports = list_reports()
    return {
        "count": len(reports),
        "reports": [
            {
                "id": r["id"],
                "target": r["target"],
                "type": r["attack"]["type"],
                "title": r["attack"].get("title"),
                "verdict": r["verdict"],
                "severity": r.get("severity"),
            }
            for r in reports
        ],
    }


@app.get("/api/reports/{rid}")
def api_report_detail(rid: str):
    report = load_report(rid)
    if report is None:
        raise HTTPException(404, f"no report {rid}")
    return report
