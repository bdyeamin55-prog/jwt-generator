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

# Ignore SSL certificate warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AES encryption key and initialization vector
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session

# Store job status in memory (in production, use Redis or database)
jobs = {}
jobs_lock = threading.Lock()

# Rotating User Agents to avoid detection
USER_AGENTS = [
    "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    "Dalvik/2.1.0 (Linux; U; Android 10; SM-G975F Build/QP1A.190711.020)",
    "Dalvik/2.1.0 (Linux; U; Android 11; Pixel 5 Build/RD1A.201105.003)",
    "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016)",
    "Dalvik/2.1.0 (Linux; U; Android 8.1.0; Redmi Note 5 Build/O11019)",
    "Dalvik/2.1.0 (Linux; U; Android 13; SM-S908B Build/TP1A.220624.014)",
    "Dalvik/2.1.0 (Linux; U; Android 7.1.2; Redmi 4X Build/N2G47H)"
]

# Proxy list (optional - if you have proxies)
PROXIES = []  # Add your proxies here if available

def get_token(password, uid, retry_count=5):
    """
    Obtain an OAuth token with aggressive retry mechanism
    """
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    
    for attempt in range(retry_count):
        try:
            headers = {
                "Host": "100067.connect.garena.com",
                "User-Agent": random.choice(USER_AGENTS),
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            }
            data = {
                "uid": uid,
                "password": password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                "client_id": "100067"
            }
            
            # Exponential backoff
            if attempt > 0:
                wait_time = min(2 ** attempt + random.uniform(1, 5), 30)
                logger.info(f"Retry {attempt + 1} for UID {uid}, waiting {wait_time:.2f}s")
                time.sleep(wait_time)
            
            # Rotate proxy if available
            proxy = None
            if PROXIES:
                proxy = random.choice(PROXIES)
            
            response = requests.post(
                url, 
                headers=headers, 
                data=data, 
                timeout=45,
                verify=False,
                proxies=proxy
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully got token for UID {uid}")
                return response.json()
            elif response.status_code == 429:  # Too Many Requests
                logger.warning(f"Rate limited for UID {uid}, waiting longer...")
                time.sleep(random.uniform(10, 20))
            elif response.status_code == 403:
                logger.error(f"Access forbidden for UID {uid}")
                return None
            else:
                logger.warning(f"Attempt {attempt + 1} failed for UID {uid}: Status {response.status_code}")
                
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout for UID {uid}, attempt {attempt + 1}")
            time.sleep(random.uniform(5, 10))
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error for UID {uid}, attempt {attempt + 1}")
            time.sleep(random.uniform(5, 10))
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for UID {uid}: {e}")
            time.sleep(random.uniform(3, 8))
    
    logger.error(f"Failed to get token for UID {uid} after {retry_count} attempts")
    return None

def encrypt_message(key, iv, plaintext):
    """Encrypt message with AES CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response(response_content):
    """Parse response string to dictionary"""
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_single_account(account_data, max_retries=5):
    """
    Process a single account with maximum retries
    """
    uid = account_data.get('uid')
    password = account_data.get('password')
    
    if not uid or not password:
        return {
            "uid": uid,
            "error": "Missing UID or password",
            "success": False,
            "attempts": 0
        }
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Processing UID {uid}, attempt {attempt + 1}/{max_retries}")
            
            # Get OAuth token
            token_data = get_token(password, uid, retry_count=3)
            if not token_data:
                if attempt < max_retries - 1:
                    continue
                return {
                    "uid": uid,
                    "error": "Failed to get OAuth token after all retries",
                    "success": False,
                    "attempts": attempt + 1
                }

            # Create game data
            game_data = my_pb2.GameData()
            game_data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
            game_data.ip_address = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
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

            # Serialize and encrypt
            serialized_data = game_data.SerializeToString()
            encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
            hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

            # Send login request
            url = "https://loginbp.ggblueshark.com/MajorLogin"
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Connection': "Keep-Alive",
                'Accept-Encoding': "gzip",
                'Content-Type': "application/octet-stream",
                'X-GA': "v1 1",
                'X-Unity-Version': "2018.4.11f1",
                'ReleaseVersion': "OB52"
            }
            
            edata = bytes.fromhex(hex_encrypted_data)
            
            # Random delay between attempts
            time.sleep(random.uniform(3, 7))
            
            response = requests.post(url, data=edata, headers=headers, verify=False, timeout=45)
            
            if response.status_code == 200:
                example_msg = output_pb2.Garena_420()
                try:
                    example_msg.ParseFromString(response.content)
                    parsed_resp = parse_response(str(example_msg))
                    token = parsed_resp.get("token", "N/A")
                    
                    if token != "N/A":
                        logger.info(f"Successfully generated token for UID {uid}")
                        return {
                            "uid": uid,
                            "token": token,
                            "success": True,
                            "attempts": attempt + 1
                        }
                except Exception as e:
                    logger.error(f"Parse error for UID {uid}: {e}")
            
            # If we get here, try again
            if attempt < max_retries - 1:
                logger.info(f"Retrying UID {uid}, attempt {attempt + 2}/{max_retries}")
                time.sleep(random.uniform(10, 20))
                continue
                
        except Exception as e:
            logger.error(f"Exception for UID {uid} on attempt {attempt + 1}: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(random.uniform(10, 30))
    
    return {
        "uid": uid,
        "error": "Failed after maximum retries",
        "success": False,
        "attempts": max_retries
    }

def process_batch_job(job_id, accounts):
    """
    Process a batch of accounts in background
    """
    with jobs_lock:
        jobs[job_id] = {
            'status': 'processing',
            'total': len(accounts),
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'results': [],
            'start_time': datetime.now().isoformat()
        }
    
    results = []
    
    # Process accounts sequentially with delays to avoid rate limiting
    for i, account in enumerate(accounts):
        logger.info(f"Job {job_id}: Processing account {i+1}/{len(accounts)}")
        
        result = process_single_account(account, max_retries=7)  # Increased retries
        
        results.append(result)
        
        # Update job status
        with jobs_lock:
            jobs[job_id]['processed'] = i + 1
            if result.get('success'):
                jobs[job_id]['successful'] += 1
            else:
                jobs[job_id]['failed'] += 1
            jobs[job_id]['results'] = results
        
        # Add delay between accounts
        if i < len(accounts) - 1:
            delay = random.uniform(5, 15)
            logger.info(f"Job {job_id}: Waiting {delay:.2f}s before next account")
            time.sleep(delay)
    
    # Filter successful results
    successful_results = [
        {"uid": r["uid"], "token": r["token"]}
        for r in results if r.get('success')
    ]
    
    # Create output file
    output_data = successful_results
    json_output = json.dumps(output_data, indent=2)
    
    # Store the result in memory
    with jobs_lock:
        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['end_time'] = datetime.now().isoformat()
        jobs[job_id]['download_data'] = json_output
        jobs[job_id]['success_count'] = len(successful_results)
    
    logger.info(f"Job {job_id} completed: {len(successful_results)}/{len(accounts)} successful")

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start background processing"""
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
        
        # Limit maximum accounts
        max_accounts = 50  # Increased limit
        if len(accounts) > max_accounts:
            return render_template('index.html', error=f"Maximum {max_accounts} accounts at a time")
        
        # Create a unique job ID
        job_id = str(uuid.uuid4())
        
        # Start background processing
        thread = threading.Thread(target=process_batch_job, args=(job_id, accounts))
        thread.daemon = True
        thread.start()
        
        # Store job ID in session
        session['current_job'] = job_id
        
        return render_template('processing.html', 
                             job_id=job_id, 
                             total=len(accounts),
                             message=f"Processing {len(accounts)} accounts. This may take several minutes...")
        
    except json.JSONDecodeError:
        return render_template('index.html', error="Invalid JSON file format")
    except Exception as e:
        return render_template('index.html', error=f"Error: {str(e)}")

@app.route('/job-status/<job_id>')
def job_status(job_id):
    """Get job status as JSON"""
    with jobs_lock:
        job = jobs.get(job_id)
    
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    return jsonify({
        'status': job['status'],
        'total': job['total'],
        'processed': job['processed'],
        'successful': job['successful'],
        'failed': job['failed'],
        'start_time': job['start_time'],
        'end_time': job.get('end_time')
    })

@app.route('/download/<job_id>')
def download_results(job_id):
    """Download the results for a completed job"""
    with jobs_lock:
        job = jobs.get(job_id)
    
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    if job['status'] != 'completed':
        return jsonify({'error': 'Job not completed yet'}), 400
    
    # Create downloadable file
    output_file = io.BytesIO()
    output_file.write(job['download_data'].encode('utf-8'))
    output_file.seek(0)
    
    # Clean up job data after download (optional)
    # with jobs_lock:
    #     del jobs[job_id]
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        output_file,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'token_bd_{timestamp}.json'
    )

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
    result = process_single_account(account, max_retries=7)
    
    if not result.get('success'):
        return render_template('index.html', 
                             error=f"Failed after {result.get('attempts', 7)} attempts: {result.get('error', 'Unknown error')}", 
                             uid=uid, 
                             password=password)
    
    return render_template('index.html', 
                         success=True, 
                         token_data=result,
                         uid=uid, 
                         password=password)

@app.route('/history')
def history():
    """View history page with recent jobs"""
    recent_jobs = []
    with jobs_lock:
        # Get last 10 completed jobs
        for job_id, job in list(jobs.items())[-10:]:
            if job['status'] == 'completed':
                recent_jobs.append({
                    'job_id': job_id[:8],
                    'total': job['total'],
                    'successful': job['successful'],
                    'failed': job['failed'],
                    'time': job.get('end_time', job['start_time'])
                })
    
    return render_template('history.html', jobs=recent_jobs)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)
