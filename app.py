import sys
sys.path.append("/")

from flask import Flask, jsonify, request, make_response, render_template, send_file
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

# Ignore SSL certificate warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# AES encryption key and initialization vector
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

app = Flask(__name__)

def get_token(password, uid):
    """
    Obtain an OAuth token by posting the provided uid and password to the token endpoint.
    """
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
    """
    Encrypt a plaintext message using AES in CBC mode with PKCS#7 padding.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def parse_response(response_content):
    """
    Parse a string response that uses key: value pairs separated by newlines.
    """
    response_dict = {}
    lines = response_content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict

def process_single_account(uid, password):
    """
    Process a single account and return token if successful
    """
    try:
        token_data = get_token(password, uid)
        if not token_data:
            return None

        # Create and populate the protocol buffer for game data.
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
                return {
                    "uid": uid,
                    "token": parsed_resp.get("token", "N/A")
                }
            except:
                return None
        else:
            return None
    except Exception as e:
        print(f"Error processing {uid}: {e}")
        return None

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and process accounts"""
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
        
        # Process each account
        results = []
        processed = 0
        total = len(accounts)
        
        for account in accounts:
            uid = account.get('uid')
            password = account.get('password')
            
            if uid and password:
                result = process_single_account(uid, password)
                if result and result.get('token') != "N/A":
                    results.append(result)
                processed += 1
        
        # Create the output JSON
        output_data = results
        
        # Convert to JSON string
        json_output = json.dumps(output_data, indent=2)
        
        # Create a downloadable file
        output_file = io.BytesIO()
        output_file.write(json_output.encode('utf-8'))
        output_file.seek(0)
        
        return send_file(
            output_file,
            mimetype='application/json',
            as_attachment=True,
            download_name='token_bd.json'
        )
        
    except json.JSONDecodeError:
        return render_template('index.html', error="Invalid JSON file format")
    except Exception as e:
        return render_template('index.html', error=f"Error processing file: {str(e)}")

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
    
    result = process_single_account(uid, password)
    
    if not result:
        return render_template('index.html', error="Failed to generate token", uid=uid, password=password)
    
    return render_template('index.html', 
                         success=True, 
                         token_data=result,
                         uid=uid, 
                         password=password)

@app.route('/history')
def history():
    """View history page"""
    return render_template('history.html')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
