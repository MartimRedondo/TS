#!/usr/bin/env python3
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from functools import wraps
import os
import json
import base64
from typing import Dict, Any, Optional
import logging
from datetime import datetime, timedelta
import secrets
from database_manager import DatabaseManager 
from cryptography.fernet import Fernet, InvalidToken
import hmac
import hashlib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import ssl

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

LOG_FILE = 'blp_audit.log'
USER_LOG_DIR = 'logs'  
os.makedirs(USER_LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(module)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def log_user_action(action: str, level: str = "info", user: Optional[str] = None):
    from flask import has_request_context, session #import local para evitar problemas de importação circular

    if not user:
        if has_request_context() and 'user' in session:
            user_obj = session.get('user')
            if user_obj and isinstance(user_obj, dict):
                 user = user_obj.get('nome', 'anonymous_session_user')
            else:
                 user = 'anonymous_no_user_in_session'
        else:
            user = 'system_or_no_request_context'


    message = f"[{user}] {action}"

    if level == "info":
        logger.info(message)
    elif level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    else: 
        logger.debug(message)
    
    user_log_filename = f"user_{user.replace('/', '_').replace(':', '_')}.log"
    user_log_path = os.path.join(USER_LOG_DIR, user_log_filename)
    try:
        with open(user_log_path, 'a') as f:
            f.write(f"{datetime.now().isoformat()} {level.upper()} {message}\n")
    except Exception as e:
        logger.warning(f"Could not write to per-user log '{user_log_path}': {e}")


limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per hour", "50 per minute"])

KEY_FILE = "encryption_key.json"

CERT_DIR = os.environ.get('CERT_DIR', './certs')
CA_CERT = os.path.join(CERT_DIR, 'ca.crt')
SERVER_CERT = os.path.join(CERT_DIR, 'server.crt')
SERVER_KEY = os.path.join(CERT_DIR, 'server.key')

def generate_session_key(): return Fernet.generate_key()

def encrypt_response_data(data, key_bytes):
    if not key_bytes: return None
    try:
        f = Fernet(key_bytes)
        return base64.b64encode(f.encrypt(json.dumps(data).encode('utf-8'))).decode('utf-8')
    except Exception as e:
        log_user_action(f"Server-side encryption failed: {e}", level="error", user="system")
        return None

def decrypt_request_data(enc_data_str, key_bytes):
    if not key_bytes: return None
    try:
        f = Fernet(key_bytes)
        return json.loads(f.decrypt(base64.b64decode(enc_data_str.encode('utf-8'))).decode('utf-8'))
    except InvalidToken:
        log_user_action("Server-side decryption failed: Invalid token", level="error", user="system")
        return None
    except Exception as e:
        log_user_action(f"Server-side decryption failed: {e}", level="error", user="system")
        return None

def verify_request_integrity(data_str, sig, key_bytes):
    if not key_bytes: return True 
    try:
        expected_sig = hmac.new(key_bytes,data_str.encode('utf-8'),hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, sig)
    except Exception as e:
        log_user_action(f"Signature verification error: {e}", level="error", user="system")
        return False


def create_response_signature(data_str, key_bytes):
    if not key_bytes: return None
    try:
        return hmac.new(key_bytes,data_str.encode('utf-8'),hashlib.sha256).hexdigest()
    except Exception as e:
        log_user_action(f"Signature creation error: {e}", level="error", user="system")
        return None


def load_encryption_key() -> Optional[bytes]: 
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, 'r') as f: key_data = json.load(f)
            log_user_action(f"Loaded encryption key from {KEY_FILE}", level="info", user="system")
            return bytes.fromhex(key_data["key"])
        except Exception as e: log_user_action(f"Error loading encryption key: {e}", level="error", user="system"); return None
    log_user_action(f"{KEY_FILE} not found", level="warning", user="system"); return None


encryption_key = load_encryption_key()
db_manager = DatabaseManager(encryption_key=encryption_key) 
if not encryption_key and db_manager.get_encryption_key() and not os.path.exists(KEY_FILE):
    try:
        with open(KEY_FILE, 'w') as f: json.dump({"key": db_manager.get_encryption_key().hex()}, f, indent=2)
        log_user_action(f"New encryption key (from DB Manager) saved to {KEY_FILE}", level="info", user="system")
    except Exception as e: log_user_action(f"Could not save new key: {e}", level="error", user="system")


SESSION_TIMEOUT = timedelta(minutes=30)


def verify_session_integrity():
    if 'session_hash' not in session or 'user' not in session: return False
    # Ensure all expected keys are present in session['user'] for hash calculation
    user_data_for_hash = session['user']
    required_keys = ['nome', 'level', 'domains', 'is_admin']
    if not all(key in user_data_for_hash for key in required_keys):
        log_user_action("Session integrity check failed: Missing keys in user session data.", level="warning")
        return False

    data_to_hash = {
        'user': user_data_for_hash['nome'],
        'level': user_data_for_hash['level'],
        'domains': sorted(user_data_for_hash.get('domains', [])), # Handle missing domains gracefully
        'is_admin': user_data_for_hash['is_admin']
    }
    expected_hash = hashlib.sha256(json.dumps(data_to_hash, sort_keys=True).encode()).hexdigest()
    return hmac.compare_digest(session['session_hash'], expected_hash)


def require_auth(f): 
    @wraps(f)
    @limiter.limit("60 per minute")
    def decorated(*args, **kwargs):
        if 'user' not in session or 'session_key' not in session: return jsonify({'error':'Auth required','code':'AUTH_REQUIRED'}),401
        if 'last_activity' in session and datetime.now()-datetime.fromisoformat(session['last_activity']) > SESSION_TIMEOUT:
            session.clear(); return jsonify({'error':'Session expired','code':'SESSION_EXPIRED'}),401
        if not verify_session_integrity(): session.clear(); return jsonify({'error':'Session integrity fail','code':'SESSION_INVALID'}),401
        session['last_activity'] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    @require_auth 
    def decorated(*args, **kwargs):
        if not session['user'].get('is_admin',False):return jsonify({'error':'Admin required','code':'ADMIN_REQUIRED'}),403
        return f(*args, **kwargs)
    return decorated

# Função auxiliar para processar o payload do request, tratando tanto payloads encriptados como planos
def process_request_payload():
    """
    Processa o payload do request, desencriptando se necessário.
    Retorna (payload, erro, código_http)
    Se não houver erro, erro será None e código_http será None.
    """
    raw_data = request.get_json()
    if not raw_data:
        return None, 'Invalid or missing JSON payload', 400
        
    # Verificar se o payload está encriptado
    if 'encrypted_data' in raw_data and 'signature' in raw_data:
        # Obter a chave de sessão
        session_key_bytes = None
        if 'session_key' in session:
            try:
                session_key_bytes = base64.b64decode(session['session_key'])
            except Exception as e:
                log_user_action(f"Failed to decode session key from session: {e}", level="error")
                return None, 'Failed to decode session key', 500
                
        if not session_key_bytes:
            return None, 'Encrypted request received, but server has no valid session key to decrypt', 400
            
        # Verificar integridade
        encrypted_str = raw_data['encrypted_data']
        signature = raw_data['signature']
        if not verify_request_integrity(encrypted_str, signature, session_key_bytes):
            log_user_action("Request integrity verification failed", level="warning")
            return None, 'Request integrity check failed', 400
            
        # Desencriptar
        data_payload = decrypt_request_data(encrypted_str, session_key_bytes)
        if not data_payload:
            log_user_action("Request decryption failed", level="warning")
            return None, 'Failed to decrypt request data', 400
            
        return data_payload, None, None
    else:
        # Payload não encriptado
        return raw_data, None, None


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data or 'nome' not in data or 'password' not in data: return jsonify({'error':'Missing credentials'}),400
    nome = data['nome'].strip()
    
    user = db_manager.authenticate_user(nome, data['password'])
    if user:
        key_bytes = generate_session_key()
        # Ensure all keys for hash are present in `user` dict from db_manager
        s_data_for_hash = {
            'user':user['nome'],
            'level':user['level'],
            'domains':sorted(user.get('domains',[])),
            'is_admin':user.get('is_admin',False)
        }
        session['user'] = user
        session['session_key'] = base64.b64encode(key_bytes).decode('utf-8')
        session['session_hash'] = hashlib.sha256(json.dumps(s_data_for_hash, sort_keys=True).encode()).hexdigest()
        session['last_activity'] = datetime.now().isoformat()
        
        log_user_action(f"User '{nome}' logged in successfully", user=nome)
        
        response_payload = {
            'success': True,
            'message': 'Login successful',
            'user': user,
            'session_key': session['session_key']
        }
        
        return jsonify(response_payload)
    else:
        log_user_action(f"Failed login attempt for user '{nome}'", level="warning")
        return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    if 'user' in session:
        user_nome = session['user'].get('nome', 'unknown')
        log_user_action(f"User '{user_nome}' logged out", user=user_nome)
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    return jsonify({'success': False, 'message': 'Not logged in'}), 200


@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    if 'user' in session and 'session_key' in session:
        if 'last_activity' in session:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > SESSION_TIMEOUT:
                session.clear()
                return jsonify({'authenticated': False, 'reason': 'Session expired'})
        
        if not verify_session_integrity():
            session.clear()
            return jsonify({'authenticated': False, 'reason': 'Session integrity check failed'})
        
        session['last_activity'] = datetime.now().isoformat()
        return jsonify({'authenticated': True, 'user': session['user']})
    return jsonify({'authenticated': False, 'reason': 'Not logged in'})


@app.route('/api/domains/basenames', methods=['GET'])
@require_auth
def list_domain_basenames():
    # Corrigido: usar o método correto list_base_domain_names() em vez de get_domain_base_names()
    base_names = db_manager.list_base_domain_names()
    return jsonify({'success': True, 'base_domain_names': base_names})


@app.route('/api/domains', methods=['GET'])
@require_auth
def list_domain_configs():
    configs = db_manager.list_domain_configs()
    return jsonify({'success': True, 'domain_configurations': configs})


@app.route('/api/domains/config', methods=['POST'])
@require_admin
def create_domain_config():
    # Processar o payload, desencriptando se necessário
    data_payload, error, status_code = process_request_payload()
    if error:
        return jsonify({'error': error}), status_code
    
    # Verificar campos obrigatórios
    if not data_payload or 'base_name' not in data_payload or 'level' not in data_payload:
        return jsonify({'error': 'base_name and level required'}), 400
    
    base_name = data_payload['base_name'].strip()
    try:
        level = int(data_payload['level'])
    except (ValueError, TypeError):
        return jsonify({'error': 'level must be an integer'}), 400
    
    try:
        if db_manager.create_domain_config(base_name, level):
            log_user_action(f"Created domain config: {base_name} at level {level}")
            return jsonify({'success': True, 'message': 'Domain configuration created'})
        else:
            return jsonify({'error': 'Domain configuration already exists or invalid data'}), 409
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        log_user_action(f"Error creating domain config: {e}", level="error")
        return jsonify({'error': 'Server error'}), 500


@app.route('/api/domains/config', methods=['DELETE'])
@require_admin
def delete_domain_config():
    # Processar o payload, desencriptando se necessário
    data_payload, error, status_code = process_request_payload()
    if error:
        return jsonify({'error': error}), status_code
    
    # Verificar campos obrigatórios
    if not data_payload or 'base_name' not in data_payload or 'level' not in data_payload:
        return jsonify({'error': 'base_name and level required'}), 400
    
    base_name = data_payload['base_name'].strip()
    try:
        level = int(data_payload['level'])
    except (ValueError, TypeError):
        return jsonify({'error': 'level must be an integer'}), 400
    
    try:
        if db_manager.delete_domain_config(base_name, level):
            log_user_action(f"Deleted domain config: {base_name} at level {level}")
            return jsonify({'success': True, 'message': 'Domain configuration deleted'})
        else:
            return jsonify({'error': 'Domain configuration not found'}), 404
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        log_user_action(f"Error deleting domain config: {e}", level="error")
        return jsonify({'error': 'Server error'}), 500


@app.route('/api/domains/<string:base_name>', methods=['GET'])
@require_auth
def get_domain_config(base_name: str):
    level_str = request.args.get('level')
    if not level_str:
        return jsonify({'error': 'level query parameter required'}), 400
    
    try:
        level = int(level_str)
    except ValueError:
        return jsonify({'error': '"level" query parameter must be an integer'}), 400

    config = db_manager.get_domain_config(base_name, level)
    if not config: return jsonify({'error': f"No domain config for '{base_name}' at L{level}"}), 404
    
    can_write_perm = can_write_to_domain_instance(session['user'], base_name, level)
    config['can_write_by_current_user'] = can_write_perm
    return jsonify({'success': True, 'domain_config': config})



@app.route('/api/users', methods=['GET']) 
@require_admin
def list_users(): return jsonify({'success':True, 'users':db_manager.list_users()})



@app.route('/api/users', methods=['POST'])
@require_admin
def create_user_route():
    # Processar o payload, desencriptando se necessário
    data_payload, error, status_code = process_request_payload()
    if error:
        return jsonify({'error': error}), status_code
    
    # Verificar campos obrigatórios
    req_fields = ['nome', 'password', 'level', 'domains']
    if not data_payload or not all(k in data_payload for k in req_fields):
        return jsonify({'error': f'Missing fields for user creation. Required: {", ".join(req_fields)}'}), 400
    
    # Garantir que domains é uma lista
    if not isinstance(data_payload['domains'], list):
        return jsonify({'error': 'domains must be a list'}), 400
    
    try:
        if db_manager.create_user(
            data_payload['nome'],
            data_payload['password'],
            data_payload['level'],
            data_payload['domains'],
            data_payload.get('is_admin', False),
            data_payload.get('is_trusted', False)
        ):
            log_user_action(f"Created user: {data_payload['nome']}")
            return jsonify({'success': True, 'message': 'User created'}), 201
        return jsonify({'error': 'User already exists or invalid data for user creation.'}), 409
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        log_user_action(f"Create user error: {e}", level="error")
        return jsonify({'error': 'Server error'}), 500


@app.route('/api/users/<string:nome>', methods=['DELETE'])
@require_admin
def delete_user_route(nome: str):
    try:
        # Prevenir que o admin tente deletar a si mesmo diretamente
        current_admin_user = session.get('user', {}).get('nome')
        if current_admin_user == nome:
            return jsonify({'error': 'Admins cannot delete themselves directly through this endpoint.'}), 403

        if db_manager.delete_user(nome):
            log_user_action(f"Deleted user: {nome}")
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        # If db_manager.delete_user returns False, it means user was not found.
        return jsonify({'error': 'User not found'}), 404
    except ValueError as e: # Catches "Cannot delete the last admin user."
        log_user_action(f"Failed to delete user {nome}: {e}", level="warning")
        return jsonify({'error': str(e)}), 400 
    except Exception as e:
        log_user_action(f"Error deleting user {nome}: {e}", level="error")
        return jsonify({'error': 'Server error during user deletion.'}), 500


# FILE MANAGEMENT
def can_write_to_domain_instance(user_session_data: Dict[str, Any], 
                                 target_base_domain_name: str, 
                                 target_domain_instance_level: int) -> bool:
    
    user_name = user_session_data.get('nome', 'unknown_user_for_can_write_check') # Get username for logging/context

    log_user_action(f"Server-side permission check for user '{user_name}': Write to BaseDomain '{target_base_domain_name}' at L{target_domain_instance_level}", level="debug", user=user_name)

    if not db_manager.get_domain_config(target_base_domain_name, target_domain_instance_level):
        log_user_action(f"Write Denied: Domain '{target_base_domain_name}' is not configured for L{target_domain_instance_level}.", level="warning", user=user_name)
        return False
    
    can_write = db_manager._check_file_write_access(target_base_domain_name, target_domain_instance_level, user_session_data)
    
    if can_write:
        log_user_action(f"Write Granted by db_manager._check_file_write_access for '{user_name}' to '{target_base_domain_name}' L{target_domain_instance_level}", level="info", user=user_name)
    else:
        log_user_action(f"Write Denied by db_manager._check_file_write_access for '{user_name}' to '{target_base_domain_name}' L{target_domain_instance_level}", level="warning", user=user_name)
        
    return can_write


@app.route('/api/files', methods=['POST'])
@require_auth 
@limiter.limit("20 per minute") 
def upload_file():
    raw_data = request.get_json()
    data_payload = None 
    user_session_data = session['user'] # This is the complete user dict

    session_key_bytes = None
    if 'session_key' in session:
        try:
            session_key_bytes = base64.b64decode(session['session_key'])
        except Exception as e:
            log_user_action(f"Failed to decode session key from session: {e}", level="error")
            pass

    if raw_data and 'encrypted_data' in raw_data:
        if not session_key_bytes: 
            log_user_action("Sent encrypted data but no valid session key found/decoded", level="warning")
            return jsonify({'error':'Encrypted request received, but server has no valid session key to decrypt.'}), 400
        
        encrypted_str = raw_data['encrypted_data']
        signature = raw_data.get('signature','') 
        if not verify_request_integrity(encrypted_str, signature, session_key_bytes):
            log_user_action("Upload request integrity verification failed", level="warning")
            return jsonify({'error':'Request integrity check failed.'}), 400
        
        data_payload = decrypt_request_data(encrypted_str, session_key_bytes)
        if not data_payload: 
            log_user_action("Upload request decryption failed", level="warning")
            return jsonify({'error':'Failed to decrypt request data.'}), 400
    else: 
        data_payload = raw_data 

    required_fields_always = ['filename', 'domain_name', 'content']
    if not data_payload or not all(k in data_payload for k in required_fields_always):
        log_user_action("Upload request missing required fields", level="warning")
        return jsonify({'error': 'Missing required fields for file upload (filename, domain_name, content).'}), 400

    filename = data_payload['filename'].strip()
    base_domain_name = data_payload['domain_name'].strip()
    content_b64 = data_payload['content']
    
    if not filename or len(filename) > 255 or any(c in filename for c in ['/', '\\', '..']):
        log_user_action(f"Invalid filename pattern in upload request: '{filename}'", level="warning")
        return jsonify({'error': 'Invalid filename pattern.'}), 400

    try:
        content_bytes = base64.b64decode(content_b64)
    except Exception as e:
        log_user_action(f"Failed to decode base64 content: {e}", level="warning")
        return jsonify({'error': 'Invalid base64 content.'}), 400

    file_level = data_payload.get('level', user_session_data['level'])
    try:
        file_level = int(file_level) 
    except (ValueError, TypeError):
        log_user_action(f"Invalid level format: '{file_level}'", level="warning")
        return jsonify({'error': 'Invalid level format. Must be an integer.'}), 400

    if not can_write_to_domain_instance(user_session_data, base_domain_name, file_level):
        # can_write_to_domain_instance now logs detailed reasons
        return jsonify({'error': f"Write access denied to domain '{base_domain_name}' at level {file_level}."}), 403

    MAX_FILE_SIZE = 10 * 1024 * 1024 
    if len(content_bytes) > MAX_FILE_SIZE:
        log_user_action(f"Upload exceeds max file size: {len(content_bytes)} bytes", level="warning")
        return jsonify({'error': f'File size exceeds maximum of {MAX_FILE_SIZE // (1024*1024)}MB.'}), 413

    file_exists = db_manager.get_file_info(filename) is not None
    overwrite_confirmed = data_payload.get('overwrite_confirmed', False)
    
    if file_exists and not overwrite_confirmed:
        log_user_action(f"File '{filename}' exists and overwrite not confirmed")
        return jsonify({'warning': 'File exists. Confirm overwrite.', 'requires_confirmation': True}), 409

    try:
        success = db_manager.write_file(
            filename=filename,
            base_domain_name=base_domain_name,
            file_level=file_level,
            content=content_bytes,
            user_nome=user_session_data['nome'] # Though user_nome is not stored with file in db_manager yet
        )

        if success:
            log_user_action(f"File '{filename}' uploaded to domain '{base_domain_name}' (L{file_level}). Size: {len(content_bytes)}")
            response_payload_final = {
                'success': True,
                'message': 'File uploaded successfully.',
                'filename': filename,
                'domain': base_domain_name,
                'level': file_level,
                'size': len(content_bytes)
            }
            
            if session_key_bytes:
                encrypted_response_str = encrypt_response_data(response_payload_final, session_key_bytes)
                if encrypted_response_str:
                    response_signature = create_response_signature(encrypted_response_str, session_key_bytes)
                    if response_signature:
                        return jsonify({'encrypted_data': encrypted_response_str, 'signature': response_signature})
            return jsonify(response_payload_final)
        else:
            log_user_action(f"db_manager.write_file returned False for '{filename}'", level="error")
            return jsonify({'error': 'Failed to write file to database (e.g., constraint violation or internal error).'}), 500
    except ValueError as ve: # From db_manager checks
        log_user_action(f"ValueError during file write: {ve}", level="warning")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        log_user_action(f"Critical error during file write: {e}", level="error")
        return jsonify({'error': 'Internal server error during file upload.'}), 500


@app.route('/api/files', methods=['GET'])
@require_auth
def list_files():
    user_session_data = session['user']
    
    try:
        files = db_manager.list_accessible_files(user_session_data['nome'])
        
        response_payload = {
            'success': True,
            'files': files
        }
        
        session_key_bytes = None
        if 'session_key' in session:
            try:
                session_key_bytes = base64.b64decode(session['session_key'])
            except Exception as e:
                log_user_action(f"Failed to decode session key from session: {e}", level="error")
                pass
        
        if session_key_bytes:
            encrypted_response_str = encrypt_response_data(response_payload, session_key_bytes)
            if encrypted_response_str:
                response_signature = create_response_signature(encrypted_response_str, session_key_bytes)
                if response_signature:
                    return jsonify({'encrypted_data': encrypted_response_str, 'signature': response_signature})
        
        return jsonify(response_payload)
    except Exception as e:
        log_user_action(f"Error listing files: {e}", level="error")
        return jsonify({'error': 'Server error during file listing.'}), 500


@app.route('/api/files/<string:filename>', methods=['GET'])
@require_auth
def get_file(filename: str):
    user_session_data = session['user']
    
    try:
        file_info = db_manager.get_file_info(filename)
        if not file_info:
            return jsonify({'error': 'File not found.'}), 404
        
        # Check if user can read this file based on BLP model
        can_read = db_manager._check_file_read_access(file_info, user_session_data)
        if not can_read:
            log_user_action(f"Read access denied to file '{filename}'", level="warning")
            return jsonify({'error': 'Read access denied.'}), 403
        
        file_content = db_manager.retrieve_file(filename, user_session_data['nome'])
        if file_content is None:
            return jsonify({'error': 'File content not found.'}), 404
        
        response_payload = {
            'success': True,
            'filename': filename,
            'domain': file_info['domain'],
            'level': file_info['level'],
            'content': base64.b64encode(file_content).decode('utf-8')
        }
        
        session_key_bytes = None
        if 'session_key' in session:
            try:
                session_key_bytes = base64.b64decode(session['session_key'])
            except Exception as e:
                log_user_action(f"Failed to decode session key from session: {e}", level="error")
                pass
        
        if session_key_bytes:
            encrypted_response_str = encrypt_response_data(response_payload, session_key_bytes)
            if encrypted_response_str:
                response_signature = create_response_signature(encrypted_response_str, session_key_bytes)
                if response_signature:
                    return jsonify({'encrypted_data': encrypted_response_str, 'signature': response_signature})
        
        return jsonify(response_payload)
    except Exception as e:
        log_user_action(f"Error retrieving file '{filename}': {e}", level="error")
        return jsonify({'error': 'Server error during file retrieval.'}), 500


@app.route('/api/files/<string:filename>/append', methods=['POST'])
@require_auth
def append_to_file(filename: str):
    raw_data = request.get_json()
    data_payload = None
    user_session_data = session['user']
    
    session_key_bytes = None
    if 'session_key' in session:
        try:
            session_key_bytes = base64.b64decode(session['session_key'])
        except Exception as e:
            log_user_action(f"Failed to decode session key from session: {e}", level="error")
            pass
    
    if raw_data and 'encrypted_data' in raw_data:
        if not session_key_bytes:
            log_user_action("Sent encrypted data but no valid session key found/decoded", level="warning")
            return jsonify({'error': 'Encrypted request received, but server has no valid session key to decrypt.'}), 400
        
        encrypted_str = raw_data['encrypted_data']
        signature = raw_data.get('signature', '')
        if not verify_request_integrity(encrypted_str, signature, session_key_bytes):
            log_user_action("Append request integrity verification failed", level="warning")
            return jsonify({'error': 'Request integrity check failed.'}), 400
        
        data_payload = decrypt_request_data(encrypted_str, session_key_bytes)
        if not data_payload:
            log_user_action("Append request decryption failed", level="warning")
            return jsonify({'error': 'Failed to decrypt request data.'}), 400
    else:
        data_payload = raw_data
    
    if not data_payload or 'content' not in data_payload:
        log_user_action("Append request missing content field", level="warning")
        return jsonify({'error': 'Missing content field for append operation.'}), 400
    
    content_b64 = data_payload['content']
    
    try:
        content_bytes = base64.b64decode(content_b64)
    except Exception as e:
        log_user_action(f"Failed to decode base64 content: {e}", level="warning")
        return jsonify({'error': 'Invalid base64 content.'}), 400
    
    file_info = db_manager.get_file_info(filename)
    if not file_info:
        return jsonify({'error': 'File not found.'}), 404
    
    # Check if user can write to this file based on BLP model
    can_write = db_manager._check_file_write_access(file_info['domain'], file_info['level'], user_session_data)
    if not can_write:
        log_user_action(f"Write access denied to file '{filename}'", level="warning")
        return jsonify({'error': 'Write access denied.'}), 403
    
    MAX_APPEND_SIZE = 5 * 1024 * 1024  # 5MB max append size
    if len(content_bytes) > MAX_APPEND_SIZE:
        log_user_action(f"Append exceeds max size: {len(content_bytes)} bytes", level="warning")
        return jsonify({'error': f'Append size exceeds maximum of {MAX_APPEND_SIZE // (1024*1024)}MB.'}), 413
    
    try:
        # Implementar append_to_file no DatabaseManager
        # Por enquanto, vamos ler o arquivo, anexar o conteúdo e escrever de volta
        current_content = db_manager.retrieve_file(filename, user_session_data['nome'])
        if current_content is None:
            return jsonify({'error': 'Failed to read current file content.'}), 500
        
        new_content = current_content + content_bytes
        success = db_manager.write_file(
            filename=filename,
            base_domain_name=file_info['domain'],
            file_level=file_info['level'],
            content=new_content,
            user_nome=user_session_data['nome']
        )
        
        if success:
            log_user_action(f"Appended {len(content_bytes)} bytes to file '{filename}'. New size: {len(new_content)} bytes")
            
            response_payload = {
                'success': True,
                'message': 'Content appended successfully.',
                'filename': filename,
                'appended_size': len(content_bytes),
                'new_size': len(new_content)
            }
            
            if session_key_bytes:
                encrypted_response_str = encrypt_response_data(response_payload, session_key_bytes)
                if encrypted_response_str:
                    response_signature = create_response_signature(encrypted_response_str, session_key_bytes)
                    if response_signature:
                        return jsonify({'encrypted_data': encrypted_response_str, 'signature': response_signature})
            
            return jsonify(response_payload)
        else:
            log_user_action(f"Failed to append to file '{filename}'", level="error")
            return jsonify({'error': 'Failed to append to file.'}), 500
    except Exception as e:
        log_user_action(f"Error appending to file '{filename}': {e}", level="error")
        return jsonify({'error': 'Server error during append operation.'}), 500


@app.route('/api/files/<string:filename>', methods=['DELETE'])
@require_auth
def delete_file(filename: str):
    user_session_data = session['user']
    
    try:
        file_info = db_manager.get_file_info(filename)
        if not file_info:
            return jsonify({'error': 'File not found.'}), 404
        
        # Check if user can write to this file based on BLP model (write permission required for delete)
        can_write = db_manager._check_file_write_access(file_info['domain'], file_info['level'], user_session_data)
        if not can_write:
            log_user_action(f"Delete access denied to file '{filename}'", level="warning")
            return jsonify({'error': 'Delete access denied.'}), 403
        
        success = db_manager.delete_file_by_filename(filename) # Call the new method
        
        if success:
            log_user_action(f"Deleted file '{filename}'")
            
            response_payload = {
                'success': True,
                'message': 'File deleted successfully.',
                'filename': filename
            }
            
            session_key_bytes = None
            if 'session_key' in session:
                try:
                    session_key_bytes = base64.b64decode(session['session_key'])
                except Exception as e:
                    log_user_action(f"Failed to decode session key from session: {e}", level="error")
                    pass
            
            if session_key_bytes:
                encrypted_response_str = encrypt_response_data(response_payload, session_key_bytes)
                if encrypted_response_str:
                    response_signature = create_response_signature(encrypted_response_str, session_key_bytes)
                    if response_signature:
                        return jsonify({'encrypted_data': encrypted_response_str, 'signature': response_signature})
            
            return jsonify(response_payload)
        else:
            log_user_action(f"Failed to delete file '{filename}'", level="error")
            return jsonify({'error': 'Failed to delete file.'}), 500
    except Exception as e:
        log_user_action(f"Error deleting file '{filename}': {e}", level="error")
        return jsonify({'error': 'Server error during file deletion.'}), 500
    

@app.route('/api/levels', methods=['GET'])
@require_auth
def list_levels():
    levels = [
        {'value': 0, 'name': 'Top Secret'},
        {'value': 1, 'name': 'Secret'},
        {'value': 2, 'name': 'Confidential'},
        {'value': 3, 'name': 'Public'}
    ]
    
    response_payload = {
        'success': True,
        'levels': levels
    }
    
    session_key_bytes = None
    if 'session_key' in session:
        try:
            session_key_bytes = base64.b64decode(session['session_key'])
        except Exception as e:
            log_user_action(f"Failed to decode session key from session: {e}", level="error")
            pass
    
    if session_key_bytes:
        encrypted_response_str = encrypt_response_data(response_payload, session_key_bytes)
        if encrypted_response_str:
            response_signature = create_response_signature(encrypted_response_str, session_key_bytes)
            if response_signature:
                return jsonify({'encrypted_data': encrypted_response_str, 'signature': response_signature})
    
    return jsonify(response_payload)


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    log_user_action(f"Flask DEBUG mode is {'ON' if debug_mode else 'OFF'}", level="info", user="system")
    
    host = '0.0.0.0'
    port = 5001
    
    # Check if TLS certificates exist
    use_tls = os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)
    
    if use_tls:
        log_user_action(f"Iniciando servidor BLP com TLS mútuo em https://{host}:{port}", level="info", user="system")
        ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ssl_context.verify_mode = ssl.CERT_OPTIONAL
        ssl_context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
        
        if os.path.exists(CA_CERT):
            ssl_context.load_verify_locations(cafile=CA_CERT)
        
        app.run(host=host, port=port, debug=debug_mode, ssl_context=ssl_context)
    else:
        log_user_action(f"Iniciando servidor BLP sem TLS em http://{host}:{port}", level="info", user="system")
        app.run(host=host, port=port, debug=debug_mode)
