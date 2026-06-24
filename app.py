from flask import Flask, render_template, request, jsonify
import re
import urllib.parse
import pickle
import numpy as np
from datetime import datetime

app = Flask(__name__)

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc
    features['num_dots'] = hostname.count('.')
    features['has_at'] = 1 if '@' in url else 0
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features['has_ip'] = 1 if re.search(ip_pattern, hostname) else 0
    suspicious_words = ['login', 'verify', 'secure', 'bank', 'account', 'update', 
                        'confirm', 'signin', 'paypal', 'ebay', 'amazon', 'microsoft']
    features['suspicious_words'] = sum(1 for word in suspicious_words if word in url.lower())
    features['has_https'] = 1 if parsed.scheme == 'https' else 0
    features['hostname_length'] = len(hostname)
    parts = hostname.split('.')
    features['num_subdomains'] = len(parts) - 1 if len(parts) > 1 else 0
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.club', '.online', '.top']
    features['suspicious_tld'] = 1 if any(tld in hostname for tld in suspicious_tlds) else 0
    features['path_length'] = len(parsed.path)
    features['num_hyphens'] = hostname.count('-')
    features['has_double_slash'] = 1 if '//' in url else 0
    features['domain_age'] = 365
    features['num_params'] = 0 if not parsed.query else len(parsed.query.split('&'))
    features['has_uppercase'] = 1 if any(c.isupper() for c in url) else 0
    feature_names = [
        'url_length', 'num_dots', 'has_at', 'has_ip', 'suspicious_words',
        'has_https', 'hostname_length', 'num_subdomains', 'suspicious_tld',
        'path_length', 'num_hyphens', 'has_double_slash', 'domain_age',
        'num_params', 'has_uppercase'
    ]
    return [features[name] for name in feature_names]

def load_model():
    try:
        with open('phishing_model.pkl', 'rb') as f:
            model = pickle.load(f)
        return model
    except:
        return None

def train_simple_model():
    from sklearn.ensemble import RandomForestClassifier
    import pickle
    X_train = []
    y_train = []
    legit = [
        [30, 2, 0, 0, 0, 1, 15, 2, 0, 10, 0, 0, 730, 2, 0],
        [25, 1, 0, 0, 0, 1, 12, 1, 0, 8, 0, 0, 365, 1, 0],
        [40, 2, 0, 0, 1, 1, 18, 2, 0, 15, 1, 0, 540, 3, 0],
    ]
    phishing = [
        [80, 5, 1, 1, 3, 0, 35, 4, 1, 45, 3, 1, 30, 6, 1],
        [65, 4, 0, 0, 4, 0, 28, 3, 1, 32, 2, 1, 15, 4, 1],
        [95, 6, 0, 1, 5, 0, 42, 5, 1, 55, 4, 1, 5, 8, 1],
        [55, 3, 1, 0, 2, 0, 22, 2, 0, 28, 2, 0, 60, 3, 1],
    ]
    for _ in range(200):
        for l in legit:
            noisy = [x + np.random.randint(-2, 3) for x in l]
            X_train.append(noisy)
            y_train.append(0)
    for _ in range(300):
        for p in phishing:
            noisy = [x + np.random.randint(-3, 4) for x in p]
            X_train.append(noisy)
            y_train.append(1)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    with open('phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    return model

model = load_model()
if model is None:
    print("Training new model...")
    model = train_simple_model()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    url = request.form.get('url', '')
    if not url:
        return jsonify({'error': 'Please provide a URL'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        features = extract_features(url)
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        probability = model.predict_proba(features_array)[0]
        is_phishing = bool(prediction)
        confidence = float(max(probability))
        feature_names = [
            'URL Length', 'Dots in Hostname', 'Contains @', 'Contains IP', 
            'Suspicious Words', 'HTTPS', 'Hostname Length', 'Subdomains',
            'Suspicious TLD', 'Path Length', 'Hyphens', 'Double Slash',
            'Domain Age (days)', 'Query Parameters', 'Uppercase Letters'
        ]
        feature_details = [
            {'name': name, 'value': val, 'risk': 'high' if val > 50 else 'medium' if val > 25 else 'low'}
            for name, val in zip(feature_names, features)
        ]
        return jsonify({
            'url': url,
            'is_phishing': is_phishing,
            'confidence': confidence,
            'probability_phishing': probability[1],
            'features': feature_details,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': '⚠️ PHISHING DETECTED!' if is_phishing else '✅ SAFE - No phishing detected'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)