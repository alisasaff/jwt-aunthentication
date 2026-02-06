from flask import Flask, request, jsonify, make_response, redirect, url_for
import jwt
import datetime
import json
import base64

app = Flask(__name__)
FLAG = "Unl0ck{JWT_4dm1n_T4k30v3r_$ucce$$ful!}"

# Insecure: Using a simple static secret
JWT_SECRET = "super_secret_key_change_in_production"
ADMIN_USERNAME = "admin"
USERS = {
    "admin": {"password": "admin_s3cr3t_passw0rd", "role": "admin"},
    "user1": {"password": "password123", "role": "user"},
    
}

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>JWT Challenge - Login</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f4f4f4; }
            .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .login-form { display: flex; flex-direction: column; gap: 15px; max-width: 400px; margin: 0 auto; }
            input { padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
            button { background: #4CAF50; color: white; padding: 12px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            button:hover { background: #45a049; }
            .hint { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin-top: 20px; font-size: 14px; }
            .info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin-top: 20px; }
            .links { margin-top: 20px; text-align: center; }
            a { color: #007bff; text-decoration: none; margin: 0 10px; }
            a:hover { text-decoration: underline; }
            #message { margin-top: 10px; }
            #token-info { margin-top: 20px; word-break: break-all; background: #f8f9fa; padding: 15px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 JWT Authentication System</h1>
            
            <div class="info">
                <h3>Challenge Info:</h3>
                <p>Your goal: Access the admin panel to get the flag.</p>
                <p>Available users: user1/password123</p>
                <p><strong>Foot Note:</strong> please use curl in command prompt instead using broswer.</p>
            </div>
            
            <div class="login-form">
                <h3>Login</h3>
                <input type="text" id="username" placeholder="Username" value="">
                <input type="password" id="password" placeholder="Password" value="">
                <button onclick="login()">Login</button>
                <div id="message"></div>
            </div>
            
            <div class="hint">
                <h3>💡 Hint:</h3>
                <p>Check the JWT tokens and the /debug endpoint. The application might not be verifying tokens correctly...</p>
                <p><strong>Important:</strong> Try modifying the JWT algorithm or checking how tokens are verified!</p>
            </div>
            
            <div class="links">
                <a href="/admin-panel">Admin Panel</a>
                <a href="/profile">Profile (requires auth)</a>
                <a href="/debug">Debug Info</a>
            </div>
            
            <div id="token-info"></div>
        </div>
        
        <script>
            function base64UrlDecode(str) {
                // Add padding if needed
                str = str.replace(/-/g, '+').replace(/_/g, '/');
                while (str.length % 4) {
                    str += '=';
                }
                return decodeURIComponent(atob(str).split('').map(function(c) {
                    return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                }).join(''));
            }
            
            async function login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const message = document.getElementById('message');
                
                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({username, password})
                    });
                    
                    const data = await response.json();
                    
                    if (response.ok) {
                        message.innerHTML = `<span style="color: green;">✅ Login successful!</span>`;
                        
                        // Display token info
                        const token = data.token;
                        const parts = token.split('.');
                        const tokenInfo = document.getElementById('token-info');
                        
                        try {
                            const header = JSON.parse(base64UrlDecode(parts[0]));
                            const payload = JSON.parse(base64UrlDecode(parts[1]));
                            
                            tokenInfo.innerHTML = `
                                <h4>Your JWT Token:</h4>
                                <p><strong>Header:</strong> <pre>${JSON.stringify(header, null, 2)}</pre></p>
                                <p><strong>Payload:</strong> <pre>${JSON.stringify(payload, null, 2)}</pre></p>
                                <p><strong>Token:</strong> <code style="font-size: 12px; word-break: break-all; display: block; background: #f0f0f0; padding: 10px;">${token}</code></p>
                                <p><strong>Try visiting:</strong> <code style="font-size: 12px; word-break: break-all; display: block; background: #f9f9f9; padding: 10px;">
        /admin-panel?token=${token}
    </code></p>
                                <p><em>Try modifying this token to become admin!</em></p>
                            `;
                        } catch(e) {
                            tokenInfo.innerHTML = `<p>Token: ${token}</p><p>Error parsing: ${e}</p>`;
                        }
                        
                    } else {
                        message.innerHTML = `<span style="color: red;">❌ ${data.error}</span>`;
                    }
                } catch (error) {
                    message.innerHTML = `<span style="color: red;">❌ Error: ${error.message}</span>`;
                }
            }
            

        </script>
    </body>
    </html>
    '''

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if username in USERS and USERS[username]['password'] == password:
            # Create JWT token
            payload = {
                'username': username,
                'role': USERS[username]['role'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
                'iat': datetime.datetime.utcnow()
            }
            
            # PyJWT v2+ returns string, but handle both
            token_bytes = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
            token = token_bytes.decode('utf-8') if isinstance(token_bytes, bytes) else token_bytes
            
            response = make_response(jsonify({
                'message': 'Login successful',
                'token': token
            }))
            
            # Set token in cookie for convenience
            response.set_cookie('auth_token', token, httponly=True)
            return response
            
        return jsonify({'error': 'Invalid credentials'}), 401
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin-panel')
def admin_panel():
    token = request.cookies.get('auth_token') or request.args.get('token')
    
    if not token:
        return redirect('/')
    
    try:
        # VULNERABLE: Not verifying the algorithm properly!
        # This allows algorithm confusion attacks
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        
        if decoded['role'] == 'admin':
            return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Panel</title>
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f0f8ff; }}
                    .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.2); text-align: center; }}
                    h1 {{ color: #d32f2f; }}
                    .flag {{ background: #ffebee; border: 2px dashed #d32f2f; padding: 20px; margin: 30px 0; font-family: monospace; font-size: 24px; color: #d32f2f; }}
                    .success {{ color: #388e3c; font-size: 20px; margin: 20px 0; }}
                    a {{ display: inline-block; margin-top: 20px; padding: 10px 20px; background: #1976d2; color: white; text-decoration: none; border-radius: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🛡️ Admin Panel</h1>
                    <p class="success">Welcome, {decoded['username']}! You have successfully authenticated as admin.</p>
                    
                    <div class="flag">
                        🚩 FLAG: {FLAG}
                    </div>
                    
                    <p>Congratulations! You've exploited the JWT vulnerability.</p>
                    <a href="/">Return to Login</a>
                </div>
            </body>
            </html>
            '''
        else:
            return jsonify({'error': f'Admin access required. Your role: {decoded.get("role", "unknown")}'}), 403
            
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 401

@app.route('/profile')
def profile():
    token = request.cookies.get('auth_token') or request.args.get('token')
    
    if not token:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        # Also vulnerable in the same way
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return jsonify({
            'username': decoded['username'],
            'role': decoded['role'],
            'expires': decoded['exp'],
            'token_header': jwt.get_unverified_header(token)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 401

@app.route('/debug')
def debug():
    """Debug endpoint - reveals hints"""
    return jsonify({
        'hint': 'Check the source code or use algorithm confusion',
        'algorithm_hint': 'What happens when different algorithms are mixed?',
        'common_vulnerabilities': [
            'Algorithm "none"',
            'Weak secrets',
            'Algorithm confusion (RS256 vs HS256)'
        ],
        'note': 'The application uses HS256 with a static secret',
        'jwt_key': JWT_SECRET  # Intentionally revealing for this challenge
    })

#@app.route('/jwt-tool')
def jwt_tool():
    """Helpful tool for crafting JWTs"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>JWT Crafting Tool</title>
        <style>
            body { font-family: monospace; padding: 20px; max-width: 1000px; margin: 0 auto; }
            .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            textarea, input { width: 100%; margin: 5px 0; font-family: monospace; padding: 10px; }
            button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; margin: 5px; }
            .result { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; }
            pre { white-space: pre-wrap; word-break: break-all; }
        </style>
    </head>
    <body>
        <h1>🔧 JWT Crafting Tool</h1>
        
        <div class="section">
            <h3>Method 1: Create "none" algorithm JWT</h3>
            <p>This creates a JWT with algorithm "none" (no signature required)</p>
            <textarea id="payload-none" rows="8">{
  "username": "admin",
  "role": "admin",
  "exp": 9999999999
}</textarea>
            <button onclick="createNoneToken()">Create "none" Algorithm Token</button>
            <div id="none-token" class="result"></div>
        </div>
        
        <div class="section">
            <h3>Method 2: Create HS256 token with known secret</h3>
            <p>Secret: <code>super_secret_key_change_in_production</code></p>
            <textarea id="payload-hs256" rows="8">{
  "username": "admin",
  "role": "admin",
  "exp": 9999999999
}</textarea>
            <button onclick="createHS256Token()">Create HS256 Token</button>
            <div id="hs256-token" class="result"></div>
        </div>
        
        <div class="section">
            <h3>Decode JWT Token</h3>
            <input type="text" id="token-input" placeholder="Paste JWT token here">
            <button onclick="decodeToken()">Decode Token</button>
            <div id="decoded" class="result"></div>
        </div>
        
        <div class="section">
            <h3>Quick Test Links</h3>
            <button onclick="testRegularUser()">Test Regular User Token</button>
            <button onclick="testNoneAdmin()">Test "none" Admin Token</button>
            <button onclick="testHS256Admin()">Test HS256 Admin Token</button>
        </div>
        
        <script>
            function base64UrlEncode(str) {
                return btoa(str)
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=+$/, '');
            }
            
            function base64UrlDecode(str) {
                str = str.replace(/-/g, '+').replace(/_/g, '/');
                while (str.length % 4) {
                    str += '=';
                }
                return atob(str);
            }
            
            function createNoneToken() {
                try {
                    const payload = JSON.parse(document.getElementById('payload-none').value);
                    const header = base64UrlEncode(JSON.stringify({alg: "none", typ: "JWT"}));
                    const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
                    const token = header + '.' + payloadEncoded + '.';
                    
                    document.getElementById('none-token').innerHTML = 
                        `<p><strong>Generated Token:</strong></p>
                         <pre>${token}</pre>
                         <p><a href="/admin-panel?token=${encodeURIComponent(token)}" target="_blank">🔗 Try this token in Admin Panel</a></p>
                         <p><a href="/profile?token=${encodeURIComponent(token)}" target="_blank">🔗 Test this token in Profile</a></p>`;
                } catch(e) {
                    alert('Invalid JSON: ' + e);
                }
            }
            
            function createHS256Token() {
                try {
                    const payload = JSON.parse(document.getElementById('payload-hs256').value);
                    // Note: This won't actually sign it, just shows the format
                    const header = base64UrlEncode(JSON.stringify({alg: "HS256", typ: "JWT"}));
                    const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
                    
                    document.getElementById('hs256-token').innerHTML = 
                        `<p><strong>Note:</strong> This only creates the header and payload. To actually sign it, you need to:</p>
                         <ol>
                           <li>Use the secret: <code>super_secret_key_change_in_production</code></li>
                           <li>Generate HMAC SHA256 signature</li>
                           <li>Or use a JWT library</li>
                         </ol>
                         <p><strong>Header + Payload:</strong></p>
                         <pre>${header}.${payloadEncoded}.[SIGNATURE]</pre>`;
                } catch(e) {
                    alert('Invalid JSON: ' + e);
                }
            }
            
            function decodeToken() {
                const token = document.getElementById('token-input').value;
                const parts = token.split('.');
                if(parts.length !== 3) {
                    alert('Invalid JWT format. Expected 3 parts separated by dots.');
                    return;
                }
                
                try {
                    const header = JSON.parse(base64UrlDecode(parts[0]));
                    const payload = JSON.parse(base64UrlDecode(parts[1]));
                    
                    document.getElementById('decoded').innerHTML = 
                        `<h4>Header:</h4><pre>${JSON.stringify(header, null, 2)}</pre>
                         <h4>Payload:</h4><pre>${JSON.stringify(payload, null, 2)}</pre>
                         <h4>Signature (base64):</h4><pre>${parts[2]}</pre>`;
                } catch(e) {
                    alert('Error decoding: ' + e);
                }
            }
            
            function testRegularUser() {
                // Simulate getting a user token
                document.getElementById('username').value = 'user1';
                document.getElementById('password').value = 'password123';
                alert('Fill login form with user1 credentials. Click Login to get a regular user token.');
            }
            
            function testNoneAdmin() {
                const payload = {
                    "username": "admin",
                    "role": "admin",
                    "exp": 9999999999
                };
                const header = base64UrlEncode(JSON.stringify({alg: "none", typ: "JWT"}));
                const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
                const token = header + '.' + payloadEncoded + '.';
                
                window.open(`/admin-panel?token=${encodeURIComponent(token)}`, '_blank');
            }
            
            function testHS256Admin() {
                alert('To create a valid HS256 admin token:\n\n1. Use the secret: super_secret_key_change_in_production\n2. Sign with HMAC SHA256\n3. Or use: python -c "import jwt; print(jwt.encode({\'username\':\'admin\',\'role\':\'admin\',\'exp\':9999999999}, \'super_secret_key_change_in_production\', algorithm=\'HS256\'))"');
            }
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    print("=" * 60)
    print("JWT CTF Challenge - Admin Takeover")
    print("=" * 60)
    print(f"Access: http://localhost:5000")
    print(f"Admin Panel: http://localhost:5000/admin-panel")
    print(f"JWT Tool: http://localhost:5000/jwt-tool")
    print(f"\nGoal: Get the flag: {FLAG}")
    print("\nUsers:")
    print("  admin / admin_s3cr3t_passw0rd")
    print("  user1 / password123")
    print("  john  / doe123")
    print("\nHint: Try algorithm 'none' or use the JWT secret!")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=1337)