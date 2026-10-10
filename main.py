"""
main.py - FastAPI backend.   Run:  uvicorn main:app --reload
Detection, severity and report building are deterministic (engine.py);
the local Llama 3 model (llm.py) only writes the narrative.
"""
from fastapi import FastAPI, File, Form, HTTPException, UploadFile

import llm
from engine import DEFAULT_PRIVILEGED, Settings, run_analysis

MAX_UPLOAD_BYTES = 20 * 1024 * 1024

app = FastAPI(title="SOC Brute-Force IR Generator API", version="2.0")


@app.get("/health")
def health():
    return {"api": "online", "ollama": llm.ollama_status()}


@app.post("/analyze-logs")
async def analyze_logs(
    file: UploadFile = File(...),
    custom_rules: str = Form(""),
    min_failures: int = Form(3),
    privileged_accounts: str = Form(",".join(DEFAULT_PRIVILEGED)),
    firewall: str = Form("iptables"),
    critical_on_privileged: bool = Form(False),
    use_llm: bool = Form(True),
):
    if firewall not in ("iptables", "ufw", "firewalld", "all"):
        raise HTTPException(status_code=422, detail="firewall must be iptables, ufw, firewalld or all")
    if not 1 <= min_failures <= 1000:
        raise HTTPException(status_code=422, detail="min_failures must be between 1 and 1000")

    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Log file larger than 20 MB")

    settings = Settings(
        min_failures=min_failures,
        privileged=[p.strip() for p in privileged_accounts.split(",") if p.strip()],
        firewall=firewall,
        critical_on_privileged=critical_on_privileged,
        custom_rules=custom_rules,
        use_llm=use_llm,
    )
    try:
        return run_analysis(content.decode("utf-8", errors="ignore"), file.filename or "upload.log",
                            settings, narrative_fn=llm.generate_narrative)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
