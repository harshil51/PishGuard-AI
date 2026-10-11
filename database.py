import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "phishguard.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            defanged_url TEXT NOT NULL,
            risk_score REAL NOT NULL,
            safety_score REAL NOT NULL,
            verdict TEXT NOT NULL,
            threat_count INTEGER DEFAULT 0,
            indicators_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_scan(url, defanged_url, risk_score, safety_score, verdict, threat_count, indicators):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (url, defanged_url, risk_score, safety_score, verdict, threat_count, indicators_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        defanged_url,
        round(risk_score, 2),
        round(safety_score, 2),
        verdict,
        threat_count,
        json.dumps(indicators),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, defanged_url, risk_score, safety_score, verdict, threat_count, indicators_json, created_at
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = []
    for row in rows:
        results.append({
            "id": row["id"],
            "url": row["url"],
            "defanged_url": row["defanged_url"],
            "risk_score": row["risk_score"],
            "safety_score": row["safety_score"],
            "verdict": row["verdict"],
            "threat_count": row["threat_count"],
            "indicators": json.loads(row["indicators_json"]) if row["indicators_json"] else [],
            "created_at": row["created_at"]
        })
    conn.close()
    return results

def get_scan_stats():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total = cursor.fetchone()["total"]
    
    cursor.execute("SELECT COUNT(*) as phishing FROM scans WHERE verdict = 'PHISHING'")
    phishing = cursor.fetchone()["phishing"]
    
    cursor.execute("SELECT COUNT(*) as safe FROM scans WHERE verdict = 'SAFE'")
    safe = cursor.fetchone()["safe"]
    
    cursor.execute("SELECT COUNT(*) as suspicious FROM scans WHERE verdict = 'SUSPICIOUS'")
    suspicious = cursor.fetchone()["suspicious"]
    
    conn.close()
    return {
        "total_scans": total,
        "phishing_count": phishing,
        "safe_count": safe,
        "suspicious_count": suspicious
    }

def clear_all_scans():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return True

# Initialize tables on import
init_db()
