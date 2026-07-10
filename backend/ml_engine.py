import math
from collections import Counter
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

SUSPICIOUS_WORDS = ['login', 'bank', 'secure', 'account', 'paypal', 'support', 'update', 'verify', 'auth', 'web', 'wallet', 'crypto']

def calculate_entropy(s):
    if not s: return 0
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def extract_features(domain):
    """ Extract numerical features from a domain string for the ML model """
    # basic cleaning
    d = domain.lower().replace("www.", "")
    base = d.rsplit('.', 1)[0] if '.' in d else d
    
    return {
        'length': len(base),
        'entropy': calculate_entropy(base),
        'num_digits': sum(c.isdigit() for c in base),
        'num_hyphens': base.count('-'),
        'has_sus_keyword': 1 if any(word in base for word in SUSPICIOUS_WORDS) else 0
    }

class MLRiskPredictor:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self._train_initial_model()
        
    def _train_initial_model(self):
        # Synthetic dataset: Good domains vs Bad domains
        # 0 = Safe, 1 = Phishing
        
        safe_domains = [
            "google.com", "facebook.com", "apple.com", "microsoft.com", "amazon.com",
            "github.com", "netflix.com", "twitter.com", "wikipedia.org", "linkedin.com",
            "spotify.com", "reddit.com", "yahoo.com", "bing.com", "instagram.com",
            "whatsapp.com", "zoom.us", "adobe.com", "paypal.com", "wordpress.org"
        ]
        
        bad_domains = [
            "secure-login-update.com", "verify-account-info.net", "paypal-auth-web.xyx",
            "bank-secure-portal.login.com", "fb-support-verify.com", "update-apple-wallet.io",
            "s3cure-auth.net", "a83kf9-login.com", "verify-security-alert.org", "crypto-wallet-verify.com",
            "support-team-secure.io", "web-auth-login.com", "login-bank-account.xyz", "secure-update.com",
            "verify-paypal.com", "auth-login-check.com", "account-alert-security.net", "admin-auth.com",
            "secure-payment-verify.com", "web-support-auth.com"
        ]
        
        data = []
        for d in safe_domains:
            f = extract_features(d)
            f['label'] = 0
            data.append(f)
            
        for d in bad_domains:
            f = extract_features(d)
            f['label'] = 1
            data.append(f)
            
        df = pd.DataFrame(data)
        X = df[['length', 'entropy', 'num_digits', 'num_hyphens', 'has_sus_keyword']]
        y = df['label']
        
        self.model.fit(X, y)
        print("🤖 AI Risk Scoring Model Trained Successfully!")
        
    def predict_risk(self, domain):
        """ Returns risk score as a percentage string (e.g. 85) """
        f = extract_features(domain)
        df_f = pd.DataFrame([f])
        
        # predict_proba returns [[prob_0, prob_1]]
        prob_phishing = self.model.predict_proba(df_f)[0][1]
        
        return int(prob_phishing * 100)

# Singleton instance
risk_engine = MLRiskPredictor()
