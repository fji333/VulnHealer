"""
VulnHealer REST API
FastAPI server for programmatic integration with CI/CD and IDEs.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import tempfile
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.engine import VulnHealerEngine

app = FastAPI(
    title="VulnHealer API",
    description="AI-Powered SAST & Auto-Patch REST API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# In-memory job store (replace with Redis for production)
jobs: Dict[str, Dict] = {}


class ScanRequest(BaseModel):
    code: Optional[str] = None
    language: str = "python"
    llm_provider: str = "deepseek"
    enable_fp_filter: bool = True
    enable_patch_validation: bool = True
    semgrep_rules: Optional[List[str]] = None


class ScanResponse(BaseModel):
    job_id: str
    status: str
    message: str


def _build_config(req: ScanRequest) -> dict:
    return {
        "scanners": {
            "semgrep": {"enabled": True, "rules": req.semgrep_rules},
            "bandit": {"enabled": True}
        },
        "llm": {
            "openai_api_key": os.getenv("OPENAI_API_KEY"),
            "deepseek_api_key": os.getenv("DEEPSEEK_API_KEY"),
            "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
            "default_provider": req.llm_provider
        },
        "enable_fp_filter": req.enable_fp_filter,
        "enable_patch_validation": req.enable_patch_validation,
        "context_lines_before": 5,
        "context_lines_after": 5,
        "max_concurrent_llm": 5
    }


async def _run_scan_job(job_id: str, code: str, config: dict):
    """Background scan task."""
    jobs[job_id]["status"] = "running"
    try:
        engine = VulnHealerEngine(config)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            path = f.name

        result = await engine.scan(path)
        os.unlink(path)

        jobs[job_id]["status"] = "completed"
        jobs[job_id]["result"] = result.to_dict()
    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)


@app.get("/health")
def health():
    return {"status": "ok", "version": "2.0.0"}


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest, background: BackgroundTasks):
    """Submit code for asynchronous scanning."""
    if not req.code or not req.code.strip():
        raise HTTPException(400, "code field is required")

    import uuid
    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {"status": "queued"}

    config = _build_config(req)
    background.add_task(_run_scan_job, job_id, req.code, config)

    return ScanResponse(job_id=job_id, status="queued", message=f"Scan queued. Poll /scan/{job_id}")


@app.get("/scan/{job_id}")
def get_scan_result(job_id: str):
    """Get scan result by job ID."""
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")

    if job["status"] in ("queued", "running"):
        return {"job_id": job_id, "status": job["status"]}

    if job["status"] == "failed":
        raise HTTPException(500, job.get("error", "Unknown error"))

    return {"job_id": job_id, "status": "completed", "result": job["result"]}


@app.post("/scan/sync")
async def scan_sync(req: ScanRequest):
    """Synchronous scan (waits for result). Suitable for small files."""
    if not req.code or not req.code.strip():
        raise HTTPException(400, "code field is required")

    config = _build_config(req)
    engine = VulnHealerEngine(config)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(req.code)
        path = f.name

    try:
        result = await engine.scan(path)
        return JSONResponse(result.to_dict())
    finally:
        os.unlink(path)


@app.get("/jobs")
def list_jobs():
    return {"jobs": [{"id": k, "status": v["status"]} for k, v in jobs.items()]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
