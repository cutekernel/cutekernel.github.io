game.registerLevel(5, {
    title: "Secure the Webhook",
    description: `Level 5: Secure the Webhook

BACKGROUND:
Webhooks need proper security measures to prevent abuse. Common security features include:
- HMAC signature verification
- IP address restrictions
- Input validation
- Rate limiting

VULNERABILITY:
The current webhook implementation has several security issues:
1. Accepts any callback_url without validation
2. No HMAC signature verification
3. No IP address restrictions
4. No rate limiting

EXPLOIT DETAILS:
1. The webhook server is vulnerable to SSRF attacks
2. Anyone can register webhooks without authentication
3. The server uses a shared secret for HMAC: "supersecretkey"
4. Internal IPs should be restricted
5. The flag is in the validateFlag function

EXAMPLE:
1. Current vulnerable code:
   @app.route('/register-webhook', methods=['POST'])
   def register_webhook():
       data = request.json
       webhooks[data['event']] = data['callback_url']
       return jsonify({'status': 'success'})

2. Secure version should:
   - Verify HMAC signatures
   - Restrict internal IPs
   - Validate callback URLs
   - Implement rate limiting

YOUR TASK:
1. Analyze the webhook-server.py file
2. Identify all security issues
3. Submit the flag from the validateFlag function`,
    hint: "The webhook server has multiple security issues. Read the webhook-server.py file to find the flag in the validateFlag function.",
    files: ['README.md', 'webhook-server.py'],
    fileContents: {
        'README.md': `# Level 5: Secure the Webhook

## Understanding Webhook Security

This level focuses on securing webhook implementations against common attacks.

### Common Webhook Security Issues
1. No authentication/authorization
2. Missing input validation
3. No HMAC signature verification
4. Allowing internal IP addresses
5. Missing rate limiting

### Security Best Practices
1. Always verify HMAC signatures
2. Restrict callback URLs to external domains
3. Implement IP address whitelisting
4. Add rate limiting
5. Validate all input data

### The Vulnerable Code
The current webhook implementation has several security issues:
- Accepts any callback_url
- No HMAC verification
- No IP restrictions
- No rate limiting

### Example Secure Implementation
```python
@app.route('/register-webhook', methods=['POST'])
def register_webhook():
    # Verify HMAC signature
    signature = request.headers.get('X-Webhook-Signature')
    if not verify_hmac(request.data, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    data = request.json
    callback_url = data.get('callback_url')
    
    # Validate callback URL
    if not is_valid_url(callback_url):
        return jsonify({'error': 'Invalid callback URL'}), 400
    
    # Restrict internal IPs
    if is_internal_ip(callback_url):
        return jsonify({'error': 'Internal IPs not allowed'}), 400
    
    webhooks[data['event']] = callback_url
    return jsonify({'status': 'success'})
```

### Solution Steps
1. Read the webhook-server.py file
2. Identify all security issues
3. Find the flag in the validateFlag function`,
        'webhook-server.py': `from flask import Flask, request, jsonify
import hmac
import hashlib
import ipaddress
from urllib.parse import urlparse

app = Flask(__name__)
webhooks = {}
HMAC_SECRET = "supersecretkey"

def verify_hmac(data, signature):
    if not signature:
        return False
    expected = hmac.new(
        HMAC_SECRET.encode(),
        data,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)

def is_internal_ip(url):
    try:
        hostname = urlparse(url).hostname
        ip = ipaddress.ip_address(hostname)
        return ip.is_private
    except:
        return False

@app.route('/register-webhook', methods=['POST'])
def register_webhook():
    data = request.json
    webhooks[data['event']] = data['callback_url']
    return jsonify({'status': 'success'})

@app.route('/trigger/<event>', methods=['POST'])
def trigger_webhook(event):
    if event in webhooks:
        response = requests.post(webhooks[event], json={'event': event})
        return jsonify({'status': 'triggered', 'response': response.text})
    return jsonify({'status': 'error', 'message': 'Event not found'})

def validateFlag(flag):
    return flag == "THM{webhooks_locked_down}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)`
    },
    handleCurl: (url, args) => {
        if (url === 'http://webhook.local:5000/register-webhook') {
            return '{"status": "success"}';
        }
        return 'Error: Invalid endpoint';
    },
    validateFlag: (flag) => {
        return flag === 'THM{webhooks_locked_down}';
    }
}); 