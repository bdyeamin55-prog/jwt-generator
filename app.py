import sys
sys.path.append("/")

from flask import Flask, jsonify, request, make_response, render_template, send_file, session
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from protobuf import my_pb2, output_pb2
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning
import json
from datetime import datetime
import io
import time
import concurrent.futures
import threading
import uuid
import random
from queue import Queue
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Ignore SSL certificate warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AES encryption key and initialization vector
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Store job status
jobs = {}
jobs_lock = threading.Lock()

# Rotating User Agents
USER_AGENTS = [
    "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Dalvik/2.1.0 (Linux; U; Android 10; SM-G975F Build/QP1A.190711.020)",
    "Dalvik/2.1.0 (Linux; U; Android 11; Pixel 5 Build/RD1A.201105.003)",
    "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016)",
    "Dalvik/2.1.0 (Linux; U; Android 13; SM-S908B Build/TP1A.220624.014)",
    "Dalvik/2.1.0 (Linux; U; Android 8.1.0; Redmi Note 5 Build/O11019)",
    "Dalvik/2.1.0 (Linux; U; Android 7.1.2; Redmi 4X Build/N2G47H)",
    "Dalvik/2.1.0 (Linux; U; Android 6.0; ASUS_Z010D Build/MMB29P)"
]

# IP ranges for X-Forwarded-For
IP_RANGES = [
    "172.190.{}.{}",
    "192.168.{}.{}",
    "10.0.{}.{}",
    "172.16.{}.{}"
]

def create_session():
    """Create a requests session with retry strategy"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

# Global session pool
session_pool = [create_session() for _ in range(10)]
session_index = 0

def get_session():
    """Get a session from pool (round-robin)"""
    global session_index
    session = session_pool[session_index % len(session_pool)]
    session_index += 1
    return session

def get_random_ip():
    """Generate random IP for X-Forwarded-For"""
    ip_template = random.choice(IP_RANGES)
    return ip_template.format(
        random.randint(1, 254),
        random.randint(1, 254)
    )

def get_token_fast(password, uid):
    """
    Fast token retrieval with connection pooling
    """
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    
    try:
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": random.choice(USER_AGENTS),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "X-Forwarded-For": get_random_ip()
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        
        session = get_session()
        response = session.post(url, headers=headers, data=data, timeout=15, verify=False)
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.warning(f"Token failed for {uid}: {response.status_code}")
            return None
            
    except Exception as e:
        logger.error(f"Token error for {uid}: {e}")
        return None

def encrypt_message_fast(key, iv, plaintext):
    """Fast AES encryption"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response_fast(response_content):
    """Fast response parsing"""
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def create_game_data_fast(uid, token_data):
    """Fast game data creation"""
    game_data = my_pb2.GameData()
    
    # Set required fields quickly
    game_data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno 640"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = get_random_ip()
    game_data.language = "en"
    game_data.open_id = token_data.get('open_id', '')
    game_data.access_token = token_data.get('access_token', '')
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    
    # Set numeric fields in batch
    numeric_fields = [
        ('field_60', 32968), ('field_61', 29815), ('field_62', 2479),
        ('field_63', 914), ('field_64', 31213), ('field_65', 32968),
        ('field_66', 31213), ('field_67', 32968), ('field_70', 4),
        ('field_73', 2), ('field_76', 1), ('field_78', 6),
        ('field_79', 1), ('field_85', 1), ('field_92', 9204),
        ('field_97', 1), ('field_98', 1)
    ]
    
    for field, value in numeric_fields:
        setattr(game_data, field, value)
    
    # Set string fields
    game_data.library_path = "/data/app/com.dts.freefireth/lib/arm"
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|base.apk"
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_99 = "4"
    game_data.field_100 = "4"
    
    return game_data

def process_single_account_fast(account_data):
    """
    Ultra-fast single account processing
    """
    uid = account_data.get('uid')
    password = account_data.get('password')
    
    if not uid or not password:
        return None
    
    try:
        # Step 1: Get token (fast with connection pooling)
        token_data = get_token_fast(password, uid)
        if not token_data:
            return None
        
        # Step 2: Create game data (fast)
        game_data = create_game_data_fast(uid, token_data)
        
        # Step 3: Serialize (fast)
        serialized_data = game_data.SerializeToString()
        
        # Step 4: Encrypt (fast)
        encrypted_data = encrypt_message_fast(AES_KEY, AES_IV, serialized_data)
        hex_data = binascii.hexlify(encrypted_data).decode('utf-8')
        
        # Step 5: Send login request (fast with connection pooling)
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Connection': "keep-alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'X-GA': "v1 1",
            'X-Unity-Version': "2018.4.11f1",
            'ReleaseVersion': "OB52",
            'X-Forwarded-For': get_random_ip()
        }
        
        edata = bytes.fromhex(hex_data)
        session = get_session()
        response = session.post(url, data=edata, headers=headers, verify=False, timeout=15)
        
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            example_msg.ParseFromString(response.content)
            parsed_resp = parse_response_fast(str(example_msg))
            token = parsed_resp.get("token", "N/A")
            
            if token != "N/A":
                return {
                    "uid": uid,
                    "token": token
                }
        
        return None
        
    except Exception as e:
        logger.error(f"Error processing {uid}: {e}")
        return None

def process_batch_parallel(accounts, max_workers=20):
    """
    Process accounts in parallel for maximum speed
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_account = {
            executor.submit(process_single_account_fast, account): account 
            for account in accounts
        }
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_account):
            result = future.result()
            if result:
                results.append(result)
    
    return results

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and super fast processing"""
    if 'file' not in request.files:
        return render_template('index.html', error="No file uploaded")
    
    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', error="No file selected")
    
    if not file.filename.endswith('.json'):
        return render_template('index.html', error="Please upload a JSON file")
    
    try:
        # Read and parse the uploaded JSON file
        accounts = json.load(file)
        
        # Limit to 500 accounts for safety
        if len(accounts) > 500:
            return render_template('index.html', error="Maximum 500 accounts allowed")
        
        # Process in parallel (super fast)
        start_time = time.time()
        results = process_batch_parallel(accounts, max_workers=25)
        processing_time = time.time() - start_time
        
        # Create output JSON
        output_data = results
        
        # Add metadata
        metadata = {
            "total_processed": len(accounts),
            "successful": len(results),
            "failed": len(accounts) - len(results),
            "processing_time_seconds": round(processing_time, 2),
            "timestamp": datetime.now().isoformat()
        }
        
        # Create final output with metadata
        final_output = {
            "metadata": metadata,
            "tokens": output_data
        }
        
        # Convert to JSON string
        json_output = json.dumps(final_output, indent=2)
        
        # Create a downloadable file
        output_file = io.BytesIO()
        output_file.write(json_output.encode('utf-8'))
        output_file.seek(0)
        
        filename = f'tokens_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        return send_file(
            output_file,
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
        
    except json.JSONDecodeError:
        return render_template('index.html', error="Invalid JSON file format")
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return render_template('index.html', error=f"Error: {str(e)}")

@app.route('/upload-fast', methods=['POST'])
def upload_file_fast():
    """
    Even faster endpoint with streaming processing
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        accounts = json.load(file)
        
        # Process in parallel with maximum speed
        results = []
        total = len(accounts)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = []
            
            for account in accounts:
                future = executor.submit(process_single_account_fast, account)
                futures.append(future)
            
            # Stream results as they come
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        
        return jsonify({
            "success": True,
            "total": total,
            "successful": len(results),
            "failed": total - len(results),
            "results": results
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/token', methods=['GET', 'POST'])
def get_token_response():
    """Single token endpoint"""
    if request.method == 'POST':
        uid = request.form.get('uid')
        password = request.form.get('password')
    else:
        uid = request.args.get('uid')
        password = request.args.get('password')
    
    if not uid or not password:
        return render_template('index.html', error="UID and Password are required!")
    
    account = {"uid": uid, "password": password}
    result = process_single_account_fast(account)
    
    if not result:
        return render_template('index.html', error="Failed to generate token", uid=uid, password=password)
    
    return render_template('index.html', 
                         success=True, 
                         token_data=result,
                         uid=uid, 
                         password=password)

@app.route('/api/token', methods=['GET', 'POST'])
def api_token():
    """API endpoint for single token"""
    if request.method == 'POST':
        uid = request.form.get('uid')
        password = request.form.get('password')
    else:
        uid = request.args.get('uid')
        password = request.args.get('password')
    
    if not uid or not password:
        return jsonify({"error": "Missing parameters"}), 400
    
    account = {"uid": uid, "password": password}
    result = process_single_account_fast(account)
    
    if not result:
        return jsonify({"error": "Failed to generate token"}), 500
    
    return jsonify(result)

@app.route('/history')
def history():
    """View history page"""
    return render_template('history.html')

@app.route('/stats')
def stats():
    """API stats endpoint"""
    return jsonify({
        "status": "online",
        "version": "3.0",
        "features": ["ultra_fast", "parallel_processing", "connection_pooling", "500+ accounts"],
        "max_accounts": 500,
        "workers": 30,
        "connection_pool_size": 50
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
