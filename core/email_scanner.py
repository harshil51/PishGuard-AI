import re
from urllib.parse import urlparse

class EmailThreatScanner:
    def __init__(self, sender="", subject="", body=""):
        self.sender = (sender or "").strip()
        self.subject = (subject or "").strip()
        self.body = (body or "").strip()
        self.indicators = []
        self.risk_score = 0.0
        self.verdict = "SAFE"

    def scan(self):
        self.indicators = []
        threat_points = 0
        max_possible_points = 100
        full_text = f"{self.subject}\n{self.body}".lower()

        # 1. Sender Spoofing / Free Mail Service for Corporate Brand
        spoof_brands = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "bank", "wells fargo", "chase", "security", "support", "helpdesk"]
        free_domains = ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com", "@aol.com", "@mail.ru", "@protonmail.com"]
        
        sender_lower = self.sender.lower()
        has_brand_in_sender_name = any(brand in sender_lower for brand in spoof_brands)
        has_free_domain = any(dom in sender_lower for dom in free_domains)
        
        if has_brand_in_sender_name and has_free_domain:
            threat_points += 25
            self.indicators.append({
                "type": "danger",
                "category": "Sender Identity",
                "title": "Brand Impersonation via Free Mail Provider",
                "detail": f"Sender claims to represent an enterprise/service but is sent from a public free email domain ({self.sender})."
            })
        elif not self.sender or "@" not in self.sender:
            threat_points += 10
            self.indicators.append({
                "type": "warning",
                "category": "Sender Identity",
                "title": "Unverified or Missing Sender",
                "detail": "The sender header is missing, malformed, or unauthenticated."
            })
        else:
            self.indicators.append({
                "type": "success",
                "category": "Sender Identity",
                "title": "Standard Sender Format",
                "detail": f"Sender address follows standard domain syntax ({self.sender})."
            })

        # 2. Extreme Urgency & Threat Triggers
        urgency_patterns = [
            (r"\b(urgent|immediate action required|account (suspended|terminated|locked|restricted)|24 hours|within 12 hours|act now)\b", 
             "Artificial Urgency & Coercion", "Uses high-pressure tactics demanding immediate compliance before penalties.", 20),
            (r"\b(security alert|unauthorized login|compromised|breach detected|suspicious activity detected)\b", 
             "Security Alarm Trigger", "Manufactures panic regarding security breaches to induce hasty clicks.", 15)
        ]
        
        for pattern, title, detail, points in urgency_patterns:
            if re.search(pattern, full_text):
                threat_points += points
                self.indicators.append({
                    "type": "danger",
                    "category": "Psychological Manipulation",
                    "title": title,
                    "detail": detail
                })

        # 3. Sensitive Data & Credential Harvesting
        credential_patterns = [
            (r"\b(confirm (your )?password|verify (your )?credentials|enter (your )?pin|social security|ssn|credit card number|cvv|otp|secret key|seed phrase)\b",
             "Direct Credential / Financial Solicitation", "Solicits highly confidential security credentials directly via email or form.", 30),
            (r"\b(crypto|bitcoin|ethereum|wallet|gift card|wire transfer|western union|payment voucher)\b",
             "Untraceable Financial Request", "Mentions irreversible payment methods, cryptocurrency, or gift cards.", 20)
        ]
        
        for pattern, title, detail, points in credential_patterns:
            if re.search(pattern, full_text):
                threat_points += points
                self.indicators.append({
                    "type": "danger",
                    "category": "Payload & Intent",
                    "title": title,
                    "detail": detail
                })

        # 4. Impersonal / Generic Greetings
        generic_greetings = r"\b(dear (customer|user|client|valued member|sir/madam|account holder)|attention user)\b"
        if re.search(generic_greetings, full_text):
            threat_points += 10
            self.indicators.append({
                "type": "warning",
                "category": "Email Construction",
                "title": "Generic Impersonal Greeting",
                "detail": "Legitimate organizations typically address you by your registered first/last name."
            })

        # 5. Suspicious Links in Email Body
        found_urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", self.body)
        if found_urls:
            has_ip_url = any(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u) for u in found_urls)
            has_shortener = any(re.search(r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly", u) for u in found_urls)
            
            if has_ip_url:
                threat_points += 25
                self.indicators.append({
                    "type": "danger",
                    "category": "Embedded URLs",
                    "title": "Raw IP Address Link in Body",
                    "detail": "Contains direct numeric IP URLs designed to bypass domain reputation filters."
                })
            elif has_shortener:
                threat_points += 15
                self.indicators.append({
                    "type": "warning",
                    "category": "Embedded URLs",
                    "title": "URL Shortener Detected",
                    "detail": "Uses link-shortening services to mask the true destination endpoint."
                })
            else:
                self.indicators.append({
                    "type": "info",
                    "category": "Embedded URLs",
                    "title": f"Detected {len(found_urls)} External Link(s)",
                    "detail": "Review all embedded hyperlinks carefully before opening."
                })

        # Calculate Final Risk Score
        final_risk = min(100.0, float(threat_points))
        if final_risk >= 50.0:
            self.verdict = "PHISHING"
        elif final_risk >= 25.0:
            self.verdict = "SUSPICIOUS"
        else:
            self.verdict = "SAFE"

        return {
            "sender": self.sender,
            "subject": self.subject,
            "risk_score": final_risk,
            "safety_score": round(100.0 - final_risk, 1),
            "verdict": self.verdict,
            "indicators": self.indicators,
            "detected_urls": found_urls
        }
