from flask import Flask, render_template, request
import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

def analyze_threat(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    domain = urlparse(url).netloc.replace("www.", "")
    
    score = 0
    factors = []
    
    try:
        domain_info = whois.whois(domain)
        creation = domain_info.creation_date
        if isinstance(creation, list): creation = creation[0]
        if creation:
            age = (datetime.now() - creation).days
            if age < 180:
                score += 40
                factors.append({"msg": f"Domain is only {age} days old (High Risk)", "type": "danger"})
            else:
                factors.append({"msg": f"Domain age is established ({age} days)", "type": "safe"})
    except Exception:
        score += 20
        factors.append({"msg": "WHOIS registration data is hidden or unreachable", "type": "warning"})

    try:
        dns.resolver.resolve(domain, 'MX')
        factors.append({"msg": "Valid Email (MX) infrastructure detected", "type": "safe"})
    except Exception:
        score += 30
        factors.append({"msg": "No Email server found (Common in scams)", "type": "danger"})

    verdict = "Highly Suspicious" if score >= 50 else "Proceed with Caution" if score >= 30 else "Likely Safe"
    return {"domain": domain, "score": min(score, 100), "factors": factors, "verdict": verdict}

@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    if request.method == "POST":
        target = request.form.get("url")
        if target:
            report = analyze_threat(target)
    return render_template("index.html", report=report)
