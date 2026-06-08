from flask import Flask, render_template_string, request, jsonify
from kyber_py.ml_kem import ML_KEM_768
from Crypto.Cipher import AES

app = Flask(__name__)

# Storage matrix using standard byte objects
session_data = {
    "public_key": None,
    "secret_key": None,
    "ciphertext": None,
    "aes_payload": None,
    "shared_secret": None
}

HTML_INTERFACE = """
<!DOCTYPE html>
<html>
<head>
    <title>Post-Quantum Cryptosystem (ML-KEM)</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #0f172a; color: #f8fafc; }
        .container { max-width: 800px; margin: 0 auto; background: #1e293b; padding: 25px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
        h1 { text-align: center; color: #38bdf8; font-size: 24px; margin-bottom: 5px; }
        h4 { text-align: center; color: #94a3b8; margin-top: 0; font-weight: 400; margin-bottom: 25px;}
        h3 { color: #f1f5f9; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 20px;}
        button { background: #0284c7; color: white; border: none; padding: 12px 20px; font-size: 15px; border-radius: 6px; cursor: pointer; width: 100%; font-weight: bold; transition: 0.2s; }
        button:hover { background: #0369a1; }
        textarea { width: 100%; height: 70px; margin: 10px 0; padding: 10px; box-sizing: border-box; border: 1px solid #475569; border-radius: 6px; background: #0f172a; color: white; font-size: 15px;}
        .box { background: #0f172a; padding: 12px; border-radius: 6px; font-family: 'Courier New', Courier, monospace; word-break: break-all; margin-top: 10px; font-size: 12px; border-left: 4px solid #38bdf8; line-height: 1.4; color: #34d399;}
        .label { color: #94a3b8; font-weight: bold; font-family: sans-serif; font-size: 11px; text-transform: uppercase; display: block; margin-bottom: 2px;}
        .success-box { border-left-color: #4ade80; background: #064e3b; color: #f0fdf4; padding: 15px; font-size: 16px; font-family: sans-serif;}
    </style>
</head>
<body>
    <div class="container">
        <h1>Hybrid Post-Quantum Cryptosystem</h1>
        <h4>Demonstrating NIST FIPS 203 (ML-KEM-768) + AES-256-CTR</h4>
        
        <div>
            <h3>1. Receiver Dashboard (Laptop View)</h3>
            <button onclick="generateKeys()">Execute ML-KEM Key Generation</button>
            <div id="pk-container" style="display:none;">
                <div class="box"><span class="label">Asymmetric Public Key (pk):</span><span id="pk-box"></span></div>
                <div class="box" style="border-left-color: #f43f5e;"><span class="label">Asymmetric Secret Key (sk):</span><span id="sk-box"></span></div>
            </div>
            
            <button onclick="checkAndDecrypt()" style="background:#16a34a; display:none; margin-top:15px;" id="btn-refresh">Fetch & Decrypt Ciphertext Pipeline</button>
            
            <div id="decryption-pipeline" style="display:none;">
                <div class="box" style="border-left-color: #eab308;"><span class="label">Received Inbound Kyber Ciphertext (c):</span><span id="rx-c-box"></span></div>
                <div class="box" style="border-left-color: #a855f7;"><span class="label">Decapsulated Post-Quantum Shared Secret Key (K):</span><span id="rx-ss-box"></span></div>
                <div class="box" style="border-left-color: #a855f7;"><span class="label">Derived AES-256 Symmetric Key:</span><span id="rx-aes-box"></span></div>
                <div class="box" style="border-left-color: #eab308;"><span class="label">Inbound Encrypted Payload (Hex):</span><span id="rx-payload-box"></span></div>
                <br>
                <div id="result-box" class="box success-box"></div>
            </div>
        </div>
        
        <div>
            <h3>2. Sender Terminal (Phone View)</h3>
            <textarea id="msg-input" placeholder="Enter plain text message to transmit..."></textarea>
            <button onclick="sendEncrypted()" style="background:#ea580c;">Run PQC Encapsulation & Transmit</button>
            
            <div id="encryption-pipeline" style="display:none;">
                <div class="box" style="border-left-color: #eab308;"><span class="label">Generated Kyber Ciphertext (c):</span><span id="tx-c-box"></span></div>
                <div class="box" style="border-left-color: #a855f7;"><span class="label">Encapsulated Shared Secret Key (K):</span><span id="tx-ss-box"></span></div>
                <div class="box" style="border-left-color: #ea580c;"><span class="label">Symmetric AES-CTR Encrypted Payload:</span><span id="tx-payload-box"></span></div>
            </div>
        </div>
    </div>

    <script>
        function generateKeys() {
            fetch('/api/keygen', {method: 'POST'})
            .then(r => r.json())
            .then(data => {
                document.getElementById('pk-container').style.display = 'block';
                document.getElementById('pk-box').innerText = data.public_key_hex;
                document.getElementById('sk-box').innerText = data.secret_key_hex;
                document.getElementById('btn-refresh').style.display = 'block';
            });
        }

        function sendEncrypted() {
            let msg = document.getElementById('msg-input').value;
            if(!msg) { alert("Please type a message first!"); return; }
            
            fetch('/api/encrypt', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message: msg})
            })
            .then(r => r.json())
            .then(data => {
                if(data.error) {
                    alert(data.error);
                } else {
                    document.getElementById('encryption-pipeline').style.display = 'block';
                    document.getElementById('tx-c-box').innerText = data.kyber_ciphertext_hex;
                    document.getElementById('tx-ss-box').innerText = data.shared_secret_hex;
                    document.getElementById('tx-payload-box').innerText = data.aes_payload_hex;
                }
            });
        }

        function checkAndDecrypt() {
            fetch('/api/decrypt')
            .then(r => r.json())
            .then(data => {
                if(data.status === "waiting" || data.status === "error") {
                    alert(data.message);
                } else {
                    document.getElementById('decryption-pipeline').style.display = 'block';
                    document.getElementById('rx-c-box').innerText = data.kyber_ciphertext_hex;
                    document.getElementById('rx-ss-box').innerText = data.shared_secret_hex;
                    document.getElementById('rx-aes-box').innerText = data.aes_key_hex;
                    document.getElementById('rx-payload-box').innerText = data.aes_payload_hex;
                    document.getElementById('result-box').innerHTML = "<strong>🎯 Cryptographic Success! Decrypted Plaintext:</strong><br><br>" + data.message;
                }
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_INTERFACE)

@app.route('/api/keygen', methods=['POST'])
def keygen():
    session_data["ciphertext"] = None
    session_data["aes_payload"] = None
    
    # ML_KEM_768.keygen() returns raw bytes in v1.2.0
    pk, sk = ML_KEM_768.keygen()
    session_data["public_key"] = pk
    session_data["secret_key"] = sk
    
    return jsonify({
        "status": "keys generated", 
        "public_key_hex": pk.hex(),
        "secret_key_hex": sk.hex()
    })

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    if not session_data.get("public_key"):
        return jsonify({"error": "Generate ML-KEM keys on Laptop first!"}), 400
    
    user_message = request.json.get("message", "Empty Message")
    
    # ML_KEM_768.encaps() accepts raw public key bytes and returns raw bytes
    kyber_ciphertext, shared_secret = ML_KEM_768.encaps(session_data["public_key"])
    print("First return length:", len(kyber_ciphertext))
    print("Second return length:", len(shared_secret))
    aes_key = shared_secret[:32]
    
    nonce = b'\x00' * 8
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    aes_ciphertext = cipher.encrypt(user_message.encode('utf-8'))
    
    session_data["ciphertext"] = kyber_ciphertext
    session_data["aes_payload"] = aes_ciphertext
    session_data["shared_secret"] = shared_secret
    
    return jsonify({
        "status": "transmitted", 
        "kyber_ciphertext_hex": kyber_ciphertext.hex(),
        "shared_secret_hex": shared_secret.hex(),
        "aes_payload_hex": aes_ciphertext.hex()
    })

@app.route('/api/decrypt', methods=['GET'])
def decrypt():
    if not session_data.get("secret_key"):
        return jsonify({"status": "waiting", "message": "Click 'Execute ML-KEM Key Generation' on your laptop first!"})
        
    if not session_data.get("aes_payload") or not session_data.get("ciphertext"):
        return jsonify({"status": "waiting", "message": "No encrypted payloads found. Submit a message from your phone first!"})
    
    try:
        sk = session_data["secret_key"]
        kyber_ciphertext = session_data["ciphertext"]

        print("Ciphertext length:", len(ct_bytes))
        print("Secret key length:", len(sk_bytes))
        # ML_KEM_768.decaps() takes raw bytes and returns raw bytes
        shared_secret = ML_KEM_768.decaps(sk, kyber_ciphertext)
        aes_key = shared_secret[:32]
        
        nonce = b'\x00' * 8
        cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
        original_msg = cipher.decrypt(session_data["aes_payload"])
        
        return jsonify({
            "status": "decrypted",
            "kyber_ciphertext_hex": kyber_ciphertext.hex(),
            "shared_secret_hex": shared_secret.hex(),
            "aes_key_hex": aes_key.hex(),
            "aes_payload_hex": session_data["aes_payload"].hex(),
            "message": original_msg.decode('utf-8')
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Decapsulation failed: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True, port=8000, use_reloader=False)
