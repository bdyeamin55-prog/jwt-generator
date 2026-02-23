import sys
sys.path.append("/")

from flask import Flask, jsonify, request, make_response, render_template
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from protobuf import my_pb2, output_pb2
import os
import warnings
from urllib3.exceptions import InsecureRequestWarning

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

def process_token(uid, password):
    """
    Get token data and use it to build, serialize, encrypt, and send game data via protocol buffers.
    """
    token_data = get_token(password, uid)
    if not token_data:
        return {"error": "Failed to retrieve token"}

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

    try:
        response = requests.post(url, data=edata, headers=headers, verify=False)
        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                parsed_resp = parse_response(str(example_msg))
                return {
                    "success": True,
                    "token": parsed_resp.get("token", "N/A"),
                    "api": parsed_resp.get("api", "N/A"),
                    "region": parsed_resp.get("region", "N/A"),
                    "status": parsed_resp.get("status", "live"),
                    "full_response": str(example_msg)
                }
            except Exception as e:
                return {"success": False, "error": f"Failed to deserialize response: {e}"}
        else:
            return {"success": False, "error": f"HTTP {response.status_code} - {response.reason}"}
    except requests.RequestException as e:
        return {"success": False, "error": f"Request error: {e}"}

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/token', methods=['GET', 'POST'])
def get_token_response():
    """
    Flask endpoint to process GET/POST requests to retrieve a token.
    Requires the parameters 'uid' and 'password'.
    """
    if request.method == 'POST':
        uid = request.form.get('uid')
        password = request.form.get('password')
    else:  # GET
        uid = request.args.get('uid')
        password = request.args.get('password')
    
    if not uid or not password:
        if request.method == 'GET' and request.args:
            return jsonify({"error": "Missing parameters: uid and password are required"}), 400
        else:
            return render_template('index.html', error="UID and Password are required!")

    result = process_token(uid, password)

    if request.method == 'POST' or (request.method == 'GET' and not request.args.get('format') == 'json'):
        if "error" in result or not result.get("success", False):
            error_msg = result.get("error", "Unknown error occurred")
            return render_template('index.html', error=error_msg, uid=uid, password=password)
        
        # Format the token for display
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
    else:
        # JSON response for API calls
        if "error" in result or not result.get("success", False):
            return jsonify({"error": result.get("error", "Unknown error")}), 500
        
        ordered_result = {
            "token": result.get("token"),
            "api": result.get("api"),
            "region": result.get("region"),
            "status": result.get("status"),
            "credit": "YASIR XT!!",
            "Join For More": "Discord: YASIR XT CHEAT!!"
        }
        
        response = make_response(jsonify(ordered_result))
        response.headers["Content-Type"] = "application/json"
        return response

@app.route('/api/token', methods=['GET', 'POST'])
def api_token():
    """API endpoint that always returns JSON"""
    if request.method == 'POST':
        uid = request.form.get('uid')
        password = request.form.get('password')
    else:
        uid = request.args.get('uid')
        password = request.args.get('password')
    
    if not uid or not password:
        return jsonify({"error": "Missing parameters: uid and password are required"}), 400
    
    result = process_token(uid, password)
    
    if "error" in result or not result.get("success", False):
        return jsonify({"error": result.get("error", "Unknown error")}), 500
    
    return jsonify({
        "token": result.get("token"),
        "api": result.get("api"),
        "region": result.get("region"),
        "status": result.get("status"),
        "credit": "YASIR XT!!"
    })

@app.route('/history')
def history():
    """View recent history (mock data for now)"""
    # In a real app, you would store this in a database
    mock_history = [
        {"uid": "4205243385", "status": "success", "time": "2026-02-23 12:30:31"},
        {"uid": "4470813228", "status": "success", "time": "2026-02-23 12:31:28"},
    ]
    return render_template('history.html', history=mock_history)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)