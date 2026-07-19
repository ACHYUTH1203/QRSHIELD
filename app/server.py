from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from app.payload_detector import detect_payload
from app.rule_engine import analyze_url

app = FastAPI(title="QRShield")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

class ScanRequest(BaseModel):
    payload: str

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/analyze")
async def analyze(data: ScanRequest):
    payload = data.payload.strip()
    if not payload:
        raise HTTPException(status_code=400, detail="Payload is empty.")

    payload_type = detect_payload(payload)
    response = {
        "payload": payload,
        "payload_type": payload_type,
        "analysis": {}
    }

    if payload_type == "URL":
        response["analysis"] = analyze_url(payload)
    elif payload_type == "UPI":
        response["analysis"] = {
            "score": 0,
            "verdict": "Suspicious",
            "reasons": ["UPI Deep Link Engine Triggered"],
            "domain": "Direct Payment System",
            "protocol": "UPI",
            "checks": {"uses_http": False, "long_url": False, "contains_at": False, "uses_ip": False, "url_shortener": False, "too_many_subdomains": False, "too_many_hyphens": False, "too_many_digits": False, "suspicious_keywords": False}
        }
    else:
        response["analysis"] = {
            "score": 0,
            "verdict": "Safe",
            "reasons": ["No structural threats found."],
            "domain": "Local Content",
            "protocol": "TEXT",
            "checks": {"uses_http": False, "long_url": False, "contains_at": False, "uses_ip": False, "url_shortener": False, "too_many_subdomains": False, "too_many_hyphens": False, "too_many_digits": False, "suspicious_keywords": False}
        }

    return response