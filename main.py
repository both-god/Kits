import os
import re
import smtplib
import socket
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import exifread
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from twilio.rest import Client

app = FastAPI(title="OSINT HUB")
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ==============================================================================
# SVG LOGO GENERATOR (PYTHON ANIMATION)
# ==============================================================================
def generate_animated_logo():
    svg_content = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="100%" height="100%">
    <defs>
        <style>
            @keyframes pulse { 0% { opacity: 1; transform: scale(1); } 50% { opacity: 0.6; transform: scale(1.05); } 100% { opacity: 1; transform: scale(1); } }
            @keyframes rotate { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            @keyframes dash { 0% { stroke-dashoffset: 200; } 100% { stroke-dashoffset: 0; } }
            .eye { animation: pulse 2s infinite ease-in-out; transform-origin: center; }
            .ring { animation: rotate 10s linear infinite; transform-origin: center; }
            .scan { stroke-dasharray: 200; animation: dash 3s linear infinite; }
        </style>
        <radialGradient id="glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#00ffcc" stop-opacity="0.8"/>
            <stop offset="100%" stop-color="#00ffcc" stop-opacity="0"/>
        </radialGradient>
    </defs>
    <!-- Background Glow -->
    <circle cx="100" cy="100" r="90" fill="url(#glow)" />
    <!-- Outer Rings -->
    <circle cx="100" cy="100" r="80" fill="none" stroke="#00ffcc" stroke-width="2" class="ring" stroke-dasharray="10 20"/>
    <circle cx="100" cy="100" r="70" fill="none" stroke="#00ffcc" stroke-width="1" stroke-opacity="0.5"/>
    <!-- Central Eye -->
    <ellipse cx="100" cy="100" rx="40" ry="20" fill="none" stroke="#00ffcc" stroke-width="3" class="eye"/>
    <circle cx="100" cy="100" r="10" fill="#00ffcc" class="eye"/>
    <!-- Scanning Lines -->
    <line x1="20" y1="100" x2="180" y2="100" stroke="#00ffcc" stroke-width="2" class="scan"/>
    <text x="100" y="160" font-family="monospace" font-size="14" fill="#00ffcc" text-anchor="middle" font-weight="bold">OSINT SPIDER</text>
    </svg>"""
    with open("static/logo.svg", "w", encoding="utf-8") as f:
        f.write(svg_content)

generate_animated_logo()

# ==============================================================================
# OSINT TOOLS ENDPOINTS
# ==============================================================================

# 1. Email OSINT
@app.post("/api/email")
async def osint_email(email: str = Form(...)):
    results = {"email": email, "valid_format": False, "mx_records": [], "smtp_check": "unknown"}
    
    # Validate format
    regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(regex, email):
        return {"status": "error", "message": "Invalid email format"}

    results["valid_format"] = True
    domain = email.split('@')[1]

    # Get MX Records
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, 'MX')
        results["mx_records"] = [str(mx.exchange) for mx in mx_records]
    except Exception as e:
        results["mx_error"] = "Could not fetch MX records (dnspython missing or no MX)."

    # SMTP Ping (Simulated)
    try:
        mx_host = results["mx_records"][0] if results["mx_records"] else domain
        server = smtplib.SMTP(timeout=5)
        server.connect(mx_host, 25)
        server.helo(server.local_hostname)
        server.mail('test@example.com')
        code, message = server.rcpt(email)
        server.quit()
        results["smtp_check"] = "Exists" if code == 250 else "Not Found"
    except Exception as e:
        results["smtp_check"] = "Blocked/Timeout"

    return {"status": "success", "data": results}

# 2. Picture OSINT (EXIF & Reverse Search Links)
@app.post("/api/picture")
async def osint_picture(file: UploadFile = File(...)):
    results = {"filename": file.filename, "exif": {}, "reverse_search_links": []}
    
    # Read EXIF
    try:
        contents = await file.read()
        with open("temp_img.jpg", "wb") as f:
            f.write(contents)
        
        with open("temp_img.jpg", "rb") as f:
            tags = exifread.process_file(f)
            for tag, value in tags.items():
                if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                    results["exif"][tag] = str(value)[:100] # truncate long strings
        
        os.remove("temp_img.jpg")
    except Exception as e:
        results["exif_error"] = str(e)

    # Google Lens / Yandex / TinEye endpoints (Simulated URLs for user to upload)
    results["reverse_search_links"] = [
        "https://lens.google.com/upload",
        "https://yandex.com/images/search",
        "https://tineye.com/"
    ]

    return {"status": "success", "data": results}

# 3. Phone / SMS OSINT
@app.post("/api/phone")
async def osint_phone(phone: str = Form(...)):
    try:
        # Parse Phone Number
        parsed = phonenumbers.parse(phone, None)
        if not phonenumbers.is_valid_number(parsed):
            return {"status": "error", "message": "Invalid phone number"}

        results = {
            "number": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "carrier": carrier.name_for_number(parsed, "en"),
            "region": geocoder.description_for_number(parsed, "en"),
            "timezone": timezone.time_zones_for_number(parsed),
            "is_valid": phonenumbers.is_valid_number(parsed),
            "national_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        }
        return {"status": "success", "data": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# 4. Spam Calling (VoIP Tester)
class CallRequest(BaseModel):
    phone: str
    count: int
    sid: str
    token: str
    from_number: str

@app.post("/api/spamcall")
async def spam_call(req: CallRequest):
    # WARNING: Requires Twilio Account. Point to your own PBX/SIP for local testing.
    try:
        client = Client(req.sid, req.token)
        calls_made = 0
        
        # Loop to spam call (Bounded to count)
        for i in range(req.count):
            call = client.calls.create(
                twiml='<Response><Say>This is a test automated call.</Say></Response>',
                to=req.phone,
                from_=req.from_number
            )
            calls_made += 1
        
        return {"status": "success", "message": f"Dispatched {calls_made} calls via Twilio.", "calls": calls_made}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ==============================================================================
# FRONTEND ROUTING
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})