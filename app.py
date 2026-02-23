import sys
sys.path.append("/")

from flask import Flask, jsonify, request, make_response, render_template, send_file
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import os
import json
import warnings
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import hashlib
import threading
import time

# Ignore SSL certificate warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# AES encryption key and initialization vector
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'data/uploaded_files'

# JSON file paths
TOKEN_FILE = 'data/tokens.json'
JWT_TOKEN_FILE = 'data/jwt_tokens.json'
UPLOAD_FOLDER = 'data/uploaded_files'

# Ensure directories exist
os.makedirs('data', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Progress tracking for batch processing
processing_progress = {}
processing_results = {}

def load_tokens():
    """Load tokens from JSON file"""
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, 'r') as f:
                return json.load(f)
        else:
            return []
    except Exception as e:
        print(f"Error loading tokens: {e}")
        return []

def load_jwt_tokens():
    """Load JWT tokens from JSON file"""
    try:
        if os.path.exists(JWT_TOKEN_FILE):
            with open(JWT_TOKEN_FILE, 'r') as f:
                return json.load(f)
        else:
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

# Original functions (get_token, encrypt_message, parse_response, process_token)
def get_token(password, uid):
    """Get OAuth token"""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return None
    return response.json()

def encrypt_message(key, iv, plaintext):
    """Encrypt message with AES"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response(response_content):
    """Parse response string"""
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_token(uid, password):
    """Process token generation"""
    try:
        token_data = get_token(password, uid)
        if not token_data:
            return {
                "success": False, 
                "error": "Failed to retrieve token. Invalid UID or Password!"
            }

        # Create and populate the protocol buffer for game data.
        game_data = my_pb2.GameData()
        game_data.timestamp = "2024-12-05 18:15:32"
        game_data.game_name = "free fire"
        game_data.game_version = 1
        game_data.version_code = "1.108.3"
        game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
        game_data.device_type = "Handheld"
        game_data.network_provider = "Verizon Wireless"
        game_data.connection_type = "WIFI"
        game_data.screen_width = 1280
        game_data.screen_height = 960
        game_data.dpi = "240"
        game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
        game_data.total_ram = 5951
        game_data.gpu_name = "Adreno (TM) 640"
        game_data.gpu_version = "OpenGL ES 3.0"
        game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
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
        game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
        game_data.field_76 = 1
        game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
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

        # Serialize the protocol buffer
        serialized_data = game_data.SerializeToString()

        # Encrypt the serialized protocol buffer data using AES
        encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
        hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

        # Prepare the request to the login endpoint
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-GA': "v1 1",
            'X-Unity-Version': "2018.4.11f1",
            'ReleaseVersion': "OB52"
        }
        edata = bytes.fromhex(hex_encrypted_data)

        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                parsed_resp = parse_response(str(example_msg))
                
                # Get the JWT token
                jwt_token = parsed_resp.get("token", "N/A")
                
                # Save JWT token
                if jwt_token != "N/A":
                    save_jwt_token(uid, jwt_token)
                
                return {
                    "success": True,
                    "token": jwt_token,
                    "api": parsed_resp.get("api", "N/A"),
                    "region": parsed_resp.get("region", "N/A"),
                    "status": parsed_resp.get("status", "live")
                }
            except Exception as e:
                return {"success": False, "error": f"Failed to deserialize response: {e}"}
        else:
            return {"success": False, "error": f"HTTP {response.status_code} - {response.reason}"}
    except Exception as e:
        return {"success": False, "error": f"Request error: {e}"}

# NEW: Batch processing function
def process_batch_file(file_path, task_id):
    """Process a batch file with UID and password"""
    try:
        with open(file_path, 'r') as f:
            accounts = json.load(f)
        
        total = len(accounts)
        results = []
        
        for i, account in enumerate(accounts):
            # Update progress
            processing_progress[task_id] = {
                'current': i + 1,
                'total': total,
                'status': 'processing',
                'current_uid': account.get('uid', 'Unknown')
            }
            
            uid = account.get('uid')
            password = account.get('password') or account.get('token')  # Check both fields
            
            if not uid or not password:
                results.append({
                    'uid': uid,
                    'success': False,
                    'error': 'Missing UID or password'
                })
                continue
            
            # Process token
            result = process_token(uid, password)
            
            results.append({
                'uid': uid,
                'success': result.get('success', False),
                'token': result.get('token', 'N/A') if result.get('success') else None,
                'error': result.get('error') if not result.get('success') else None
            })
            
            # Small delay to avoid rate limiting
            time.sleep(1)
        
        # Save results
        output_file = os.path.join(UPLOAD_FOLDER, f'result_{task_id}.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Update progress
        processing_progress[task_id] = {
            'current': total,
            'total': total,
            'status': 'completed',
            'output_file': output_file
        }
        
        processing_results[task_id] = results
        
    except Exception as e:
        processing_progress[task_id] = {
            'status': 'error',
            'error': str(e)
        }

# Web Routes
@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/token', methods=['GET', 'POST'])
def get_token_response():
    """Generate token endpoint"""
    if request.method == 'POST':
        uid = request.form.get('uid')
        password = request.form.get('password')
    else:
        uid = request.args.get('uid')
        password = request.args.get('password')
    
    if not uid or not password:
        return render_template('index.html', error="UID and Password are required!")
    
    result = process_token(uid, password)
    
    if not result.get("success", False):
        return render_template('index.html', 
                             error=result.get("error", "Unknown error"), 
                             uid=uid, 
                             password=password)
    
    token_data = {
        "token": result.get("token"),
        "api": result.get("api"),
        "region": result.get("region"),
        "status": result.get("status"),
        "credit": "YASIR XT!!",
        "join": "Discord: YASIR XT CHEAT!!"
    }
    
    return render_template('index.html', 
                         success=True, 
                         token_data=token_data,
                         uid=uid, 
                         password=password)

# NEW: Upload and process JSON file
@app.route('/upload-batch', methods=['POST'])
def upload_batch():
    """Upload a JSON file with UIDs and passwords"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith('.json'):
        return jsonify({'error': 'Please upload a JSON file'}), 400
    
    try:
        # Read and validate JSON
        content = file.read().decode('utf-8')
        accounts = json.loads(content)
        
        # Validate format
        if not isinstance(accounts, list):
            return jsonify({'error': 'JSON must be an array of objects'}), 400
        
        for account in accounts:
            if 'uid' not in account:
                return jsonify({'error': 'Each object must have "uid" field'}), 400
            if 'password' not in account and 'token' not in account:
                return jsonify({'error': 'Each object must have "password" or "token" field'}), 400
        
        # Save file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'batch_{timestamp}.json'
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        with open(filepath, 'w') as f:
            json.dump(accounts, f, indent=2)
        
        # Generate task ID
        task_id = hashlib.md5(f"{timestamp}{len(accounts)}".encode()).hexdigest()[:8]
        
        # Start processing in background thread
        thread = threading.Thread(target=process_batch_file, args=(filepath, task_id))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': f'Processing {len(accounts)} accounts',
            'filename': filename
        })
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# NEW: Check batch processing progress
@app.route('/batch-progress/<task_id>')
def batch_progress(task_id):
    """Check progress of batch processing"""
    progress = processing_progress.get(task_id, {'status': 'not_found'})
    return jsonify(progress)

# NEW: Download batch results
@app.route('/batch-result/<task_id>')
def batch_result(task_id):
    """Download batch processing results"""
    progress = processing_progress.get(task_id)
    
    if not progress:
        return jsonify({'error': 'Task not found'}), 404
    
    if progress.get('status') != 'completed':
        return jsonify({'error': 'Processing not completed'}), 400
    
    output_file = progress.get('output_file')
    if not output_file or not os.path.exists(output_file):
        return jsonify({'error': 'Result file not found'}), 404
    
    return send_file(
        output_file,
        as_attachment=True,
        download_name=f'jwt_results_{task_id}.json',
        mimetype='application/json'
    )

# NEW: Download sample batch file
@app.route('/download-sample-batch')
def download_sample_batch():
    """Download a sample batch file"""
    sample = [
        {
            "uid": "4470813228",
            "password": "BD_YEAMIN_Z4WT7"
        },
        {
            "uid": "4205243385",
            "password": "your_password_here"
        },
        {
            "uid": "4511856832",
            "password": "another_password"
        }
    ]
    
    temp_file = os.path.join(UPLOAD_FOLDER, 'sample_batch.json')
    with open(temp_file, 'w') as f:
        json.dump(sample, f, indent=2)
    
    return send_file(
        temp_file,
        as_attachment=True,
        download_name='sample_batch.json',
        mimetype='application/json'
    )

# Download JWT Tokens JSON file
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
        
        temp_file = 'data/jwt_tokens_download.json'
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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
