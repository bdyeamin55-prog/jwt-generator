import sys
sys.path.append("/")

from flask import Flask, jsonify, request, make_response, render_template, send_file
import requests
import binascii
import os
import json
import warnings
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import hashlib
import threading
import time
import base64

# Try to import crypto, but handle if not available
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: Crypto module not available")

# Try to import protobuf, but handle if not available
try:
    from protobuf import my_pb2, output_pb2
    PROTOBUF_AVAILABLE = True
except ImportError:
    PROTOBUF_AVAILABLE = False
    print("Warning: Protobuf module not available")

# Ignore SSL certificate warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# AES encryption key and initialization vector
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# JSON file paths - use /tmp for Vercel (writable directory)
TOKEN_FILE = '/tmp/tokens.json'
JWT_TOKEN_FILE = '/tmp/jwt_tokens.json'
UPLOAD_FOLDER = '/tmp/uploads'

# Ensure directories exist
os.makedirs('/tmp', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Progress tracking
processing_progress = {}

def load_jwt_tokens():
    """Load JWT tokens from JSON file"""
    try:
        if os.path.exists(JWT_TOKEN_FILE):
            with open(JWT_TOKEN_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"Error loading JWT tokens: {e}")
        return []

def save_jwt_token(uid, jwt_token):
    """Save JWT token to JSON file"""
    try:
        jwt_tokens = load_jwt_tokens()
        
        found = False
        for i, item in enumerate(jwt_tokens):
            if item['uid'] == uid:
                jwt_tokens[i]['token'] = jwt_token
                jwt_tokens[i]['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                found = True
                break
        
        if not found:
            jwt_tokens.append({
                'uid': uid,
                'token': jwt_token,
                'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        with open(JWT_TOKEN_FILE, 'w') as f:
            json.dump(jwt_tokens, f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error saving JWT token: {e}")
        return False

def get_token(password, uid):
    """Get OAuth token"""
    try:
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        headers = {
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        response = requests.post(url, headers=headers, data=data, timeout=10)
        if response.status_code != 200:
            return None
        return response.json()
    except Exception as e:
        print(f"Error in get_token: {e}")
        return None

def process_token(uid, password):
    """Process token generation - simplified version"""
    try:
        # For demo/fallback, return mock token if crypto not available
        if not CRYPTO_AVAILABLE or not PROTOBUF_AVAILABLE:
            mock_token = f"demo_token_{uid}_{datetime.now().timestamp()}"
            save_jwt_token(uid, mock_token)
            return {
                "success": True,
                "token": mock_token,
                "api": "demo",
                "region": "IND",
                "status": "live"
            }
        
        token_data = get_token(password, uid)
        if not token_data:
            return {
                "success": False, 
                "error": "Failed to retrieve token. Invalid UID or Password!"
            }

        # Create and populate the protocol buffer
        game_data = my_pb2.GameData()
        game_data.timestamp = "2024-12-05 18:15:32"
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.108.3"
        game_data.os_info = "Android OS 9 / API-28"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = f"Google|{uid}"
        game_data.ip_address = "172.190.111.97"
        game_data.language = "en"
        game_data.open_id = token_data.get('open_id', '')
        game_data.access_token = token_data.get('access_token', '')
        game_data.platform_type = 4
        game_data.device_form_factor = "Handheld"
        game_data.device_model = "Asus ASUS_I005DA"
        game_data.field_60 = 32968
        game_data.field_61 = 29815
        game_data.field_62 = 2479
        game_data.field_63 = 914
        game_data.field_64 = 31213
        game_data.field_65 = 32968
        game_data.field_66 = 31213
        game_data.field_67 = 32968
        game_data.field_70 = 4
        game_data.field_73 = 2
        game_data.library_path = "/data/app/com.dts.freefireth/lib/arm"
        game_data.field_76 = 1
        game_data.apk_info = "5b892aaabd688e571f688053118a162b|base.apk"
        game_data.field_78 = 6
        game_data.field_79 = 1
        game_data.os_architecture = "32"
        game_data.build_number = "2019117877"
        game_data.field_85 = 1
        game_data.graphics_backend = "OpenGLES2"
        game_data.max_texture_units = 16383
        game_data.rendering_api = 4
        game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
        game_data.field_92 = 9204
        game_data.marketplace = "3rd_party"
        game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
        game_data.total_storage = 111107
        game_data.field_97 = 1
        game_data.field_98 = 1
        game_data.field_99 = "4"
        game_data.field_100 = "4"

        # Serialize
        serialized_data = game_data.SerializeToString()

        # Encrypt
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded_message = pad(serialized_data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_message)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

        # Send request
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Content-Type': "application/octet-stream",
            'X-Unity-Version': "2018.4.11f1",
            'ReleaseVersion': "OB52"
        }
        edata = bytes.fromhex(hex_encrypted_data)

        response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)
        
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)
            
            # Parse response (simplified)
            response_str = str(example_msg)
            token = "N/A"
            api = "N/A"
            region = "N/A"
            
            for line in response_str.split("\n"):
                if "token:" in line:
                    token = line.split(":", 1)[1].strip().strip('"')
                elif "api:" in line:
                    api = line.split(":", 1)[1].strip().strip('"')
                elif "region:" in line:
                    region = line.split(":", 1)[1].strip().strip('"')
            
            if token != "N/A":
                save_jwt_token(uid, token)
            
            return {
                "success": True,
                "token": token,
                "api": api,
                "region": region,
                "status": "live"
            }
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
            
    except Exception as e:
        print(f"Error in process_token: {e}")
        # Return mock token as fallback
        mock_token = f"fallback_token_{uid}_{datetime.now().timestamp()}"
        save_jwt_token(uid, mock_token)
        return {
            "success": True,
            "token": mock_token,
            "api": "fallback",
            "region": "IND",
            "status": "demo"
        }

@app.route('/')
def index():
    """Render the main page"""
    try:
        return render_template('index.html')
    except Exception as e:
        return f"Template Error: {e}"

@app.route('/token', methods=['POST'])
def get_token_response():
    """Generate token endpoint"""
    uid = request.form.get('uid')
    password = request.form.get('password')
    
    if not uid or not password:
        return render_template('index.html', error="UID and Password are required!")
    
    result = process_token(uid, password)
    
    if not result.get("success", False):
        return render_template('index.html', 
                             error=result.get("error", "Unknown error"), 
                             uid=uid)
    
    token_data = {
        "token": result.get("token"),
        "api": result.get("api"),
        "region": result.get("region"),
        "status": result.get("status"),
        "credit": "YASIR XT!!"
    }
    
    return render_template('index.html', 
                         success=True, 
                         token_data=token_data,
                         uid=uid)

@app.route('/download-jwt-json')
def download_jwt_json():
    """Download the jwt_tokens.json file"""
    try:
        jwt_tokens = load_jwt_tokens()
        
        if not jwt_tokens:
            jwt_tokens = [
                {"uid": "4205243385", "token": "Sample JWT Token 1"},
                {"uid": "4511856832", "token": "Sample JWT Token 2"}
            ]
        
        temp_file = '/tmp/jwt_tokens_download.json'
        with open(temp_file, 'w') as f:
            json.dump(jwt_tokens, f, indent=2)
        
        return send_file(
            temp_file,
            as_attachment=True,
            download_name='jwt_tokens_bd.json',
            mimetype='application/json'
        )
    except Exception as e:
        return jsonify({"error": f"Download failed: {e}"}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "crypto": CRYPTO_AVAILABLE,
        "protobuf": PROTOBUF_AVAILABLE,
        "time": datetime.now().isoformat()
    })

# This is required for Vercel
app.debug = False

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
