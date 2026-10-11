# PhishGuard AI - Backend Application
import os
import json
import pickle
import warnings
import numpy as np
import pandas as pd
from flask import Flask, request, render_template, jsonify, send_from_directory

warnings.filterwarnings('ignore')

from core.feature import FeatureExtraction, defang_url
from core.email_scanner import EmailThreatScanner
import core.database as db
import core.metrics_service as metrics_service

# Load trained Gradient Boosting model
model_path = os.path.join(os.path.dirname(__file__), "models", "model.pkl")
with open(model_path, "rb") as file:
    gbc = pickle.load(file)

app = Flask(__name__)

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"), "favicon.ico", mimetype="image/vnd.microsoft.icon")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            return render_template("index.html", xx=-1, scan_result=None)

        obj = FeatureExtraction(url)
        features = obj.getFeaturesList()
        x = np.array(features).reshape(1, 30)

        # Predict probabilities: class -1 (phishing) at index 0, class 1 (legitimate) at index 1
        probabilities = gbc.predict_proba(x)[0]
        y_pro_phishing = float(probabilities[0])
        y_pro_safe = float(probabilities[1])
        risk_score = round(y_pro_phishing * 100, 1)
        safety_score = round(y_pro_safe * 100, 1)

        if risk_score >= 50.0:
            verdict = "PHISHING"
        elif risk_score >= 25.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        indicators = obj.getDetailedExplanation()
        threat_count = sum(1 for ind in indicators if ind["status"] == "danger")
        defanged = obj.getDefangedUrl()

        scan_id = db.save_scan(
            url=obj.url,
            defanged_url=defanged,
            risk_score=risk_score,
            safety_score=safety_score,
            verdict=verdict,
            threat_count=threat_count,
            indicators=indicators
        )

        scan_result = {
            "id": scan_id,
            "url": obj.url,
            "raw_input": url,
            "defanged_url": defanged,
            "risk_score": risk_score,
            "safety_score": safety_score,
            "verdict": verdict,
            "threat_count": threat_count,
            "indicators": indicators,
            "is_ssrf_risk": obj.is_ssrf_risk
        }

        return render_template('index.html', xx=round(y_pro_safe, 2), url=url, scan_result=scan_result)

    return render_template("index.html", xx=-1, scan_result=None)

# --- RESTful API Endpoints for Modern Dynamic Dashboard ---

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or request.form
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"success": False, "error": "URL parameter is required."}), 400

    obj = FeatureExtraction(url)
    features = obj.getFeaturesList()
    x = np.array(features).reshape(1, 30)

    probabilities = gbc.predict_proba(x)[0]
    y_pro_phishing = float(probabilities[0])
    y_pro_safe = float(probabilities[1])
    risk_score = round(y_pro_phishing * 100, 1)
    safety_score = round(y_pro_safe * 100, 1)

    if risk_score >= 50.0:
        verdict = "PHISHING"
    elif risk_score >= 25.0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    indicators = obj.getDetailedExplanation()
    threat_count = sum(1 for ind in indicators if ind["status"] == "danger")
    defanged = obj.getDefangedUrl()

    scan_id = db.save_scan(
        url=obj.url,
        defanged_url=defanged,
        risk_score=risk_score,
        safety_score=safety_score,
        verdict=verdict,
        threat_count=threat_count,
        indicators=indicators
    )

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "url": obj.url,
        "raw_input": url,
        "defanged_url": defanged,
        "risk_score": risk_score,
        "safety_score": safety_score,
        "verdict": verdict,
        "threat_count": threat_count,
        "indicators": indicators,
        "is_ssrf_risk": obj.is_ssrf_risk
    })

@app.route("/api/scan-email", methods=["POST"])
def api_scan_email():
    data = request.get_json(silent=True) or request.form
    sender = data.get("sender", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()

    if not body and not subject:
        return jsonify({"success": False, "error": "Email subject or body content is required."}), 400

    scanner = EmailThreatScanner(sender=sender, subject=subject, body=body)
    result = scanner.scan()
    result["success"] = True
    return jsonify(result)

@app.route("/api/history", methods=["GET"])
def api_history():
    limit = request.args.get("limit", 50, type=int)
    history = db.get_recent_scans(limit=limit)
    stats = db.get_scan_stats()
    return jsonify({
        "success": True,
        "history": history,
        "stats": stats
    })

@app.route("/api/clear-history", methods=["POST"])
def api_clear_history():
    db.clear_all_scans()
    return jsonify({"success": True, "message": "Scan audit history cleared."})

@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    metrics_data = metrics_service.compute_or_load_metrics()
    return jsonify({"success": True, "metrics": metrics_data})

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)