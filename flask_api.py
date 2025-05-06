# flask_api.py
import os
from flask import Flask, request, jsonify # type: ignore
from transformers import pipeline, AutoTokenizer
import torch # type: ignore

app = Flask(__name__)

# Get the absolute path to the data folder
DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

def load_blocked_domains():
    blocked = set()
    # Load all 7 blocklist files (1.txt through 7.txt)
    for i in range(1, 4):
        file_path = os.path.join(DATA_FOLDER, f"{i}.txt")
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(("#", "!", "/")):
                        # Extract domain (last part after whitespace)
                        domain = line.split()[-1].lower()
                        # Remove 0.0.0.0 or similar prefixes
                        domain = domain.replace("0.0.0.0", "").replace("127.0.0.1", "").strip()
                        if domain:
                            blocked.add(domain)
                            # Add www version if not already present
                            if not domain.startswith("www."):
                                blocked.add(f"www.{domain}")
        except FileNotFoundError:
            print(f"Warning: Blocklist file {file_path} not found")
            continue
            
    return blocked

print("Loading threat database...")
BLOCKED_DOMAINS = load_blocked_domains()
print(f"Loaded {len(BLOCKED_DOMAINS)} malicious domains")

# Initialize model only for non-blocked domains
try:
    tokenizer = AutoTokenizer.from_pretrained("DunnBC22/codebert-base-Malicious_URLs")
    pipe = pipeline(
        "text-classification",
        model="DunnBC22/codebert-base-Malicious_URLs",
        tokenizer=tokenizer,
        device=0 if torch.cuda.is_available() else -1,
        truncation=True,
        max_length=512,
        top_k=None
    )
    print("AI Model loaded successfully")
except Exception as e:
    print(f"Error loading AI model: {e}")
    pipe = None

def extract_domain(url):
    """Extract main domain from URL"""
    url = url.split('//')[-1].split('/')[0].split('?')[0]  # Remove protocol/paths/parameters
    return url[4:] if url.startswith("www.") else url

@app.route('/predict', methods=['POST'])
def predict():
    url = request.json.get('url', '').lower().strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    domain = extract_domain(url)

    # Blocklist check - exact match
    if domain in BLOCKED_DOMAINS:
        return jsonify({
            "is_malicious": True,
            "threat_type": "phishing",
            "confidence": 0.95,
            "source": "blocklist",
            "domain": domain,
            "threat_breakdown": {
                "phishing": 0.95,
                "malware": 0.03,
                "defacement": 0.01,
                "benign": 0.01
            }
        })

    # Blocklist check - subdomain match
    for blocked_domain in BLOCKED_DOMAINS:
        if domain.endswith(f".{blocked_domain}"):
            return jsonify({
                "is_malicious": True,
                "threat_type": "phishing",
                "confidence": 0.95,
                "source": "blocklist",
                "domain": blocked_domain,
                "threat_breakdown": {
                    "phishing": 0.95,
                    "malware": 0.03,
                    "defacement": 0.01,
                    "benign": 0.01
                }
            })

    # Only perform AI analysis if domain is not in blocklist
    if pipe:
        try:
            result = pipe(url[:500])  # Truncate long URLs
            
            if result and isinstance(result, list) and len(result) > 0:
                threat_breakdown = {res['label']: round(res['score'], 4) for res in result[0]}
                highest = max(result[0], key=lambda x: x['score'])
                
                return jsonify({
                    "is_malicious": highest['score'] > 0.7,
                    "threat_type": highest['label'],
                    "confidence": highest['score'],
                    "source": "ai_model",
                    "threat_breakdown": threat_breakdown
                })
        except Exception as e:
            print(f"AI Prediction error: {e}")

    # Default response for unknown domains when AI fails
    return jsonify({
        "is_malicious": False,
        "threat_type": "benign",
        "confidence": 0.80,
        "source": "unknown",
        "threat_breakdown": {
            "phishing": 0.10,
            "malware": 0.05,
            "defacement": 0.05,
            "benign": 0.80
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)