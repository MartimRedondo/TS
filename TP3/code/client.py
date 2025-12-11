#!/usr/bin/env python3
import requests
import json
import base64
import os
import sys
import gc
from typing import Dict, Any, Optional, List, Set
import getpass
import argparse
from cryptography.fernet import Fernet, InvalidToken
import hmac
import hashlib
import ssl
import threading
import time
import logging
import tempfile
import platform
import subprocess
import atexit

# Importar os módulos de refresh e limpeza
from session_refresher import SessionRefresher
from secure_cleanup import SecureCleanup

# Configuração de logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('BLPClient')

class BLPClient:
    def __init__(self, server_url: str = "https://localhost:5001", 
                 ca_cert: Optional[str] = None,
                 client_cert: Optional[str] = None,
                 client_key: Optional[str] = None,
                 session_refresh_interval: int = 600,  # 10 minutos por padrão
                 verbose: bool = False):
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()
        self.verbose = verbose
        
        # Configuração TLS com autenticação mútua
        if ca_cert:
            # Verificar certificado do servidor usando CA
            self.session.verify = ca_cert
        else:
            # warning and skip CA verification
            self.session.verify = False
            print("Warning: No CA certificate provided. SSL verification is disabled. This is insecure!")

        # Autenticação do cliente com certificado
        if client_cert and client_key:
            self.session.cert = (client_cert, client_key)
        
        self.current_user: Optional[Dict[str, Any]] = None
        self.authenticated: bool = False
        self.session_key_bytes: Optional[bytearray] = None

        self.security_levels = {0:"Top Secret",1:"Secret",2:"Confidential",3:"Public"}
        self.colors = {'RED':'\033[91m','GREEN':'\033[92m','YELLOW':'\033[93m','BLUE':'\033[94m','CYAN':'\033[96m','BOLD':'\033[1m','END':'\033[0m'}
        
        # Inicializar o refresher de sessão
        self.session_refresher = SessionRefresher(
            refresh_callback=self.check_auth_status,
            interval=session_refresh_interval,
            verbose=verbose
        )
        
        # Inicializar o gestor de limpeza segura
        self.secure_cleanup = SecureCleanup(verbose=verbose)
        
        # Registar função de limpeza para execução no encerramento
        atexit.register(self._cleanup_on_exit)

    def _cleanup_on_exit(self):
        """Função chamada automaticamente quando o programa termina"""
        if self.authenticated:
            self.logout(force=True)
        
    def _colorize(self, text: str, color_name: str) -> str:
        return f"{self.colors.get(color_name.upper(),'')}{text}{self.colors['END']}"

    def _print_message(self, message: str, color: str, prefix: str = ""):
        print(self._colorize(f"{prefix}{message}", color))

    # Ensure these methods are correctly defined like this:
    def print_error(self, message: str): self._print_message(message, 'RED', "❌ Error: ")
    def print_success(self, message: str): self._print_message(message, 'GREEN', "✅ Success: ")
    def print_warning(self, message: str): self._print_message(message, 'YELLOW', "⚠️ Warning: ")
    def print_info(self, message: str): self._print_message(message, 'BLUE', "ℹ️ Info: ")

    def _encrypt_payload(self, payload: Dict[str, Any]) -> Optional[str]:
        if not self.session_key_bytes:
            self.print_warning("Session key not available for encryption. Payload will not be encrypted.")
            return None
        try:
            fernet = Fernet(self.session_key_bytes)
            encrypted = fernet.encrypt(json.dumps(payload).encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            self.print_error(f"Client-side encryption failed: {type(e).__name__} - {e}")
            return None

    def _decrypt_payload(self, encrypted_str: str) -> Optional[Dict[str, Any]]:
        if not self.session_key_bytes:
            self.print_warning("Session key not available for decryption. Cannot decrypt payload.")
            return None
        try:
            fernet = Fernet(self.session_key_bytes)
            decrypted_bytes = fernet.decrypt(base64.b64decode(encrypted_str.encode('utf-8')))
            return json.loads(decrypted_bytes.decode('utf-8'))
        except InvalidToken:
            self.print_error("Client-side decryption failed: Invalid token (key mismatch or corrupted data).")
            return None
        except Exception as e:
            self.print_error(f"Client-side decryption failed: {type(e).__name__} - {e}")
            return None

    def _create_signature(self, data_str: str) -> Optional[str]:
        if not self.session_key_bytes:
            self.print_warning("Session key not available for signing.") 
            return None
        try:
            return hmac.new(self.session_key_bytes, data_str.encode('utf-8'), hashlib.sha256).hexdigest()
        except Exception as e:
            self.print_error(f"Client-side signature creation failed: {e}")
            return None

    def _verify_signature(self, data_str: str, signature: str) -> bool:
        if not self.session_key_bytes:
            self.print_info("No session key, skipping signature verification for received message.")
            return True 
        try:
            expected_sig = self._create_signature(data_str)
            if expected_sig is None:
                self.print_error("Failed to create expected signature for verification.")
                return False
            return hmac.compare_digest(expected_sig, signature)
        except Exception as e:
            self.print_error(f"Client-side signature verification failed: {e}")
            return False

    def make_request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        json_to_send = None

        if data:
            # Specific endpoints like login/status are handled by not passing self.session_key_bytes if needed prior to call
            if self.session_key_bytes and endpoint not in ['/api/auth/login', '/api/auth/status']: 
                encrypted_data_str = self._encrypt_payload(data)
                if encrypted_data_str:
                    signature = self._create_signature(encrypted_data_str)
                    if signature:
                        json_to_send = {'encrypted_data': encrypted_data_str, 'signature': signature}
                    else:
                        self.print_warning("Failed to create signature for encrypted data. Sending original data unencrypted.")
                        json_to_send = data 
                else:
                    self.print_warning("Encryption failed. Sending original data unencrypted.")
                    json_to_send = data 
            else:
                json_to_send = data 
        
        try:
            response = self.session.request(method, url, json=json_to_send, params=params, headers=headers, timeout=15)
            
            if response.status_code == 204: 
                return {'success': True, 'message': 'Operation successful (No Content).'}

            try:
                res_json = response.json()
            except json.JSONDecodeError:
                if 200 <= response.status_code < 300:
                     return {'error': f'Server returned non-JSON success (Status {response.status_code})', 'raw_content': response.text[:500]}
                response.raise_for_status() 
                return {'error': f'HTTP error: {response.status_code} {response.reason}. Response not JSON.', 'raw_response': response.text[:200]}

            if not (200 <= response.status_code < 300):
                 response.raise_for_status()

            if 'encrypted_data' in res_json and 'signature' in res_json:
                if not self.session_key_bytes:
                    return {'error': 'Received encrypted response but client has no session key for decryption.'}
                
                encrypted_response_str = res_json['encrypted_data']
                if self._verify_signature(encrypted_response_str, res_json['signature']):
                    decrypted_res = self._decrypt_payload(encrypted_response_str)
                    if decrypted_res:
                        # self.print_info("Encrypted response successfully decrypted and verified.") # Too verbose
                        return decrypted_res
                    else: 
                        return {'error': 'Failed to decrypt server response though signature was valid.'}
                else:
                    return {'error': 'Server response signature verification failed. Data might be tampered.'}
            
            # self.print_info(f"Received unencrypted JSON response from {url}.") # Too verbose
            return res_json

        except requests.exceptions.SSLError as e:
            self.print_error(f"Erro SSL: {e}")
            return {'error': f'Erro SSL: {e}'}
        except requests.exceptions.HTTPError as e:
            self.print_error(f"HTTP error from server: {e.response.status_code} {e.response.reason}")
            try:
                return e.response.json()
            except json.JSONDecodeError: 
                return {'error': f'HTTP error: {e.response.status_code} {e.response.reason}. Raw: {e.response.text[:200]}'}
        except requests.exceptions.Timeout:
            return {'error': f'Request to {url} timed out.'}
        except requests.exceptions.ConnectionError: # Catch only ConnectionError for this specific message
            return {'error': f'Could not connect to server at {url}. Please ensure server is running.'}
        except requests.exceptions.RequestException as e: # Broader network/request errors
             return {'error': f'A network or request error occurred: {e}'}
        except Exception as e: 
            self.print_error(f"An unexpected error occurred in make_request: {type(e).__name__} - {e}")
            return {'error': f'Client-side request processing error: {e}'}

    def login(self, username: Optional[str] = None, password: Optional[str] = None) -> bool:
        # Parar o refresher se estiver em execução
        if self.session_refresher.is_running():
            self.session_refresher.stop()
            
        if not username: username = input("Username: ").strip()
        if not password: password = getpass.getpass("Password: ")
        
        payload = {'nome': username, 'password': password}
        # Login request is always unencrypted initially by client, then Server sends back session key if successful
        _current_key = self.session_key_bytes
        self.session_key_bytes = None
        response = self.make_request('POST', '/api/auth/login', data=payload)
        self.session_key_bytes = _current_key # Restore, though it will be overwritten if login is successful

        if response.get('success'):
            self.current_user = response['user']
            self.authenticated = True
            if 'session_key' in response:
                try:
                    # Usar bytearray em vez de bytes para permitir sobrescrita segura
                    key_bytes = base64.b64decode(response['session_key'])
                    self.session_key_bytes = bytearray(key_bytes)
                    self.print_info("Secure session established with server.")
                except Exception as e:
                    self.print_error(f"Failed to decode session key from server: {e}")
                    self.session_key_bytes = None
                    self.authenticated = False 
                    return False
            else:
                self.print_warning("No session key received from server. Communication may be unencrypted if server allows.")
                self.session_key_bytes = None

            self.print_success(f"Logged in as {self.current_user.get('nome')}")
            
            # Iniciar o refresher de sessão
            self.session_refresher.start()
            
            return True
        else:
            self.print_error(response.get('error', 'Login failed. Check credentials and server status.'))
            return False

    def logout(self, force: bool = False) -> bool:
        if not self.authenticated and not force:
            self.print_warning("Not logged in.")
            return False
            
        # Parar o refresher de sessão
        if self.session_refresher.is_running():
            self.session_refresher.stop()
        
        # Guardar nome de utilizador para mensagem final
        logged_out_username = self.current_user.get('nome', 'user') if self.current_user else 'user'
        
        # Enviar pedido de logout ao servidor se autenticado
        if self.authenticated:
            response = self.make_request('POST', '/api/auth/logout')
            server_logout_success = response.get('success', False)
        else:
            server_logout_success = True  # Se não estiver autenticado, não há necessidade de logout no servidor
        
        # Limpar dados sensíveis em memória
        if self.session_key_bytes:
            self.secure_cleanup.secure_clear_bytes(self.session_key_bytes)
        
        # Limpar objetos sensíveis
        if self.current_user:
            self.secure_cleanup.secure_clear_object(self.current_user)
        
        # Definir variáveis como None após limpeza
        self.current_user = None
        self.authenticated = False
        self.session_key_bytes = None
        
        # Executar limpeza completa
        self.secure_cleanup.secure_logout_cleanup(
            clear_memory=True,
            clear_downloads=True,
            clear_temp=True,
            clear_history=True,
            clear_terminal=False  # Não limpar terminal para mostrar mensagem de logout
        )
        
        # Forçar garbage collection
        gc.collect()
        
        if server_logout_success:
            self.print_success(f"Successfully logged out {logged_out_username} from server.")
            return True
        else:
            self.print_error(response.get('error', f"Logout command failed on server for {logged_out_username}."))
            return False

    def check_auth_status(self) -> bool:
        if not self.authenticated:
            return False
            
        _current_key = self.session_key_bytes
        self.session_key_bytes = None
        response = self.make_request('GET', '/api/auth/status')
        self.session_key_bytes = _current_key

        if response.get('authenticated'):
            self.current_user = response['user'] # Don't overwrite self.session_key_bytes here; it's established at login
            self.authenticated = True
            if self.verbose:
                self.print_info("Session refreshed successfully.")
            return True
        else:
            self.authenticated = False
            self.current_user = None
            self.session_key_bytes = None 
            self.print_info(f"Session expired or invalid. Reason: {response.get('reason', 'N/A')}")
            return False

    def print_user_info(self, user_data: Optional[Dict[str, Any]] = None):
        ud = user_data or self.current_user
        if not ud: self.print_info("No user logged in."); return
        lvl_name = self.security_levels.get(ud['level'], str(ud['level']))

        print(f"\n{self._colorize('User Info:', 'CYAN BOLD')}")
        print(f"  Username: {ud['nome']}")
        print(f"  Level:    {lvl_name} (Value: {ud['level']})")
        print(f"  Domains:  {', '.join(ud.get('domains',[]))}")
        print(f"  Admin:    {'Yes' if ud.get('is_admin', False) else 'No'}")
        print(f"  Trusted:  {'Yes' if ud.get('is_trusted', False) else 'No'}")

    def list_files(self):
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
        
        res = self.make_request('GET', '/api/files')
        
        if res.get('success'):
            files = res.get('files', [])
            if not files:
                self.print_info("No files available.")
                return
            
            print(f"\n{self._colorize('Available Files:', 'CYAN')}")
            print(f"{'Filename':<30} {'Domain':<15} {'Level':<10}")
            print("-" * 55)
            for file in sorted(files, key=lambda x: x['filename']):
                level_name = self.security_levels.get(file['level'], str(file['level']))
                print(f"  {file['filename']:<28} {file['domain']:<15} {level_name:<10}")
        else:
            self.print_error(res.get('error', 'Failed to list files.'))

    def retrieve_file(self, filename: str, save_path: Optional[str] = None):
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
        
        res = self.make_request('GET', f'/api/files/{filename}')
        
        if res.get('success'):
            content = res.get('content')
            if not content:
                self.print_error("File content is empty or missing.")
                return
            
            try:
                decoded_content = base64.b64decode(content)
                
                if save_path:
                    with open(save_path, 'wb') as f:
                        f.write(decoded_content)
                    self.secure_cleanup.register_downloaded_file(save_path)
                    self.print_success(f"File saved to {save_path}")
                else:
                    try:
                        # Try to decode as text
                        text_content = decoded_content.decode('utf-8')
                        print(f"\n{self._colorize('File Content:', 'CYAN')}")
                        print(text_content)
                    except UnicodeDecodeError:
                        # If not text, show binary info
                        self.print_info(f"Binary file, size: {len(decoded_content)} bytes")
                        self.print_info("Use save option to view binary files.")
            except Exception as e:
                self.print_error(f"Error processing file content: {e}")
        else: self.print_error(res.get('error',f"Failed to get file '{filename}'"))

    def upload_file_interactive(self):
        if not self.authenticated or not self.current_user:
            self.print_error("Not authenticated properly.")
            return
        
        filename = input("Enter filename for server storage: ").strip()
        base_domain_name = input("Enter base domain name: ").strip()
        
        # Default to user's level if not specified
        level_input = input(f"Enter security level (default: {self.current_user['level']}): ").strip()
        level = self.current_user['level']
        if level_input:
            try:
                level = int(level_input)
            except ValueError:
                self.print_error("Invalid level format. Using user's level as default.")
        
        file_path = input("Enter local file path to upload: ").strip()
        if not os.path.isfile(file_path):
            self.print_error(f"File not found: {file_path}")
            return
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            payload = {
                'filename': filename,
                'domain_name': base_domain_name,
                'level': level,
                'content': base64.b64encode(content).decode('utf-8')
            }
            
            res = self.make_request('POST', '/api/files', data=payload)
            
            if res.get('requires_confirmation'):
                confirm = input("File exists. Overwrite? (y/n): ").strip().lower()
                if confirm == 'y':
                    payload['overwrite_confirmed'] = True
                    res = self.make_request('POST', '/api/files', data=payload)
                else:
                    self.print_info("Upload canceled.")
                    return
            
            if res.get('success'):
                self.print_success(f"File '{filename}' uploaded successfully to domain '{base_domain_name}' at level {level}.")
            else:
                self.print_error(res.get('error', 'Unknown error during upload.'))
        
        except Exception as e:
            self.print_error(f"Error uploading file: {e}")

    def append_file_interactive(self):
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
        
        filename = input("Enter filename to append to: ").strip()
        file_path = input("Enter local file path with content to append: ").strip()
        
        if not os.path.isfile(file_path):
            self.print_error(f"File not found: {file_path}")
            return
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            payload = {
                'content': base64.b64encode(content).decode('utf-8')
            }
            
            res = self.make_request('POST', f'/api/files/{filename}/append', data=payload)
            
            if res.get('success'):
                self.print_success(f"Content appended to file '{filename}' successfully.")
                if 'new_size' in res:
                    self.print_info(f"New file size: {res['new_size']} bytes")
            else:
                self.print_error(res.get('error', 'Unknown error during append operation.'))
        
        except Exception as e:
            self.print_error(f"Error appending to file: {e}")

    def delete_file(self, filename):
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
        
        confirm = input(f"Are you sure you want to delete '{filename}'? (y/n): ").strip().lower()
        if confirm != 'y':
            self.print_info("Deletion canceled.")
            return
        
        res = self.make_request('DELETE', f'/api/files/{filename}')
        
        if res.get('success'):
            self.print_success(f"File '{filename}' deleted successfully.")
        else:
            self.print_error(res.get('error', 'Unknown error during file deletion.'))

    def list_domains(self):
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
        
        res = self.make_request('GET', '/api/domains/basenames')
        
        if res.get('success'):
            base_names = res.get('base_domain_names', [])
            if not base_names:
                self.print_info("No domain base names configured.")
                return
            
            print(f"\n{self._colorize('Available Domain Base Names:', 'CYAN')}")
            for name in base_names:
                print(f"  {name}")
        else:
            self.print_error(res.get('error', 'Failed to list domain base names.'))

    def list_levels(self):
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
        
        res = self.make_request('GET', '/api/levels')
        
        if res.get('success'):
            levels = res.get('levels', [])
            if not levels:
                self.print_info("No security levels configured.")
                return
            
            print(f"\n{self._colorize('Security Levels:', 'CYAN')}")
            print(f"{'Value':<10} {'Name':<20}")
            print("-" * 30)
            for level in sorted(levels, key=lambda x: x['value']):
                print(f"  {level['value']:<8} {level['name']:<20}")
        else:
            self.print_error(res.get('error', 'Failed to list security levels.'))

    def configure_session_refresh(self):
        """Configurar o refresh automático de sessão"""
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
            
        print(f"\n{self._colorize('Session Refresh Configuration:', 'CYAN')}")
        
        # Mostrar configuração atual
        status = self.session_refresher.get_status()
        print(f"Current status: {'Active' if status['running'] else 'Inactive'}")
        print(f"Current interval: {status['interval']} seconds")
        
        # Opções
        print("\nOptions:")
        print("1. Enable auto-refresh")
        print("2. Disable auto-refresh")
        print("3. Change refresh interval")
        print("0. Back")
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == '1':
            if not status['running']:
                self.session_refresher.start()
                self.print_success("Session auto-refresh enabled.")
            else:
                self.print_info("Session auto-refresh is already enabled.")
                
        elif choice == '2':
            if status['running']:
                self.session_refresher.stop()
                self.print_success("Session auto-refresh disabled.")
            else:
                self.print_info("Session auto-refresh is already disabled.")
                
        elif choice == '3':
            try:
                new_interval = int(input("Enter new interval in seconds (min 60): ").strip())
                if new_interval < 60:
                    self.print_warning("Interval too short. Minimum is 60 seconds.")
                    new_interval = 60
                    
                self.session_refresher.set_interval(new_interval)
                self.print_success(f"Refresh interval set to {new_interval} seconds.")
                
                # Reiniciar se estava ativo
                if status['running']:
                    self.session_refresher.stop()
                    self.session_refresher.start()
                    
            except ValueError:
                self.print_error("Invalid input. Please enter a number.")
                
        elif choice == '0':
            return
            
        else:
            self.print_error("Invalid choice.")

    def manage_downloaded_files(self):
        """Gerir ficheiros descarregados durante a sessão"""
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
            
        if not self.secure_cleanup.downloaded_files:
            self.print_info("No downloaded files in this session.")
            return
            
        print(f"\n{self._colorize('Downloaded Files:', 'CYAN')}")
        for i, filepath in enumerate(sorted(self.secure_cleanup.downloaded_files), 1):
            print(f"{i}. {filepath}")
            
        print("\nOptions:")
        print("1. Delete all files")
        print("2. Delete specific file")
        print("0. Back")
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == '1':
            self.secure_cleanup.cleanup_downloaded_files(ask_confirmation=True)
        elif choice == '2':
            try:
                file_idx = int(input("Enter file number to delete: ").strip()) - 1
                files = sorted(self.secure_cleanup.downloaded_files)
                if 0 <= file_idx < len(files):
                    filepath = files[file_idx]
                    if self.secure_cleanup.secure_delete_file(filepath):
                        self.secure_cleanup.downloaded_files.remove(filepath)
                        self.print_success(f"File deleted: {filepath}")
                    else:
                        self.print_error(f"Failed to delete file: {filepath}")
                else:
                    self.print_error("Invalid file number.")
            except ValueError:
                self.print_error("Invalid input. Please enter a number.")
        elif choice == '0':
            return
        else:
            self.print_error("Invalid choice.")

    # ===== FUNÇÕES PARA ADMINISTRAÇÃO =====

    def list_users(self):
        """Listar todos os utilizadores (apenas admin)"""
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
            
        if not self.current_user.get('is_admin', False):
            self.print_error("Admin privileges required.")
            return
            
        res = self.make_request('GET', '/api/users')
        
        if res.get('success'):
            users = res.get('users', [])
            if not users:
                self.print_info("No users found.")
                return
                
            print(f"\n{self._colorize('Users:', 'CYAN')}")
            print(f"{'Username':<20} {'Level':<10} {'Admin':<8} {'Trusted':<8} {'Domains'}")
            print("-" * 80)
            
            for user in sorted(users, key=lambda x: x['nome']):
                level_name = self.security_levels.get(user['level'], str(user['level']))
                is_admin = "Yes" if user.get('is_admin', False) else "No"
                is_trusted = "Yes" if user.get('is_trusted', False) else "No"
                domains = ", ".join(user.get('domains', []))
                
                print(f"{user['nome']:<20} {level_name:<10} {is_admin:<8} {is_trusted:<8} {domains}")
        else:
            self.print_error(res.get('error', 'Failed to list users.'))

    def create_user(self):
        """Criar um novo utilizador (apenas admin)"""
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
            
        if not self.current_user.get('is_admin', False):
            self.print_error("Admin privileges required.")
            return
            
        # Obter informações do novo utilizador
        nome = input("Enter username: ").strip()
        if not nome:
            self.print_error("Username cannot be empty.")
            return
            
        password = getpass.getpass("Enter password: ")
        if not password:
            self.print_error("Password cannot be empty.")
            return
            
        # Listar níveis disponíveis
        res_levels = self.make_request('GET', '/api/levels')
        if not res_levels.get('success'):
            self.print_error(res_levels.get('error', 'Failed to get security levels.'))
            return
            
        levels = res_levels.get('levels', [])
        if not levels:
            self.print_error("No security levels configured.")
            return
            
        print(f"\n{self._colorize('Available Security Levels:', 'CYAN')}")
        for level in sorted(levels, key=lambda x: x['value']):
            print(f"  {level['value']}: {level['name']}")
            
        # Obter nível de segurança
        try:
            level = int(input("\nEnter security level: ").strip())
            # Verificar se o nível existe
            if not any(l['value'] == level for l in levels):
                self.print_warning(f"Level {level} not found in available levels. Proceeding anyway.")
        except ValueError:
            self.print_error("Invalid level format. Must be an integer.")
            return
            
        # Listar domínios disponíveis
        res_domains = self.make_request('GET', '/api/domains/basenames')
        if not res_domains.get('success'):
            self.print_error(res_domains.get('error', 'Failed to get domains.'))
            return
            
        base_names = res_domains.get('base_domain_names', [])
        if not base_names:
            self.print_warning("No domain base names configured.")
            
        if base_names:
            print(f"\n{self._colorize('Available Domain Base Names:', 'CYAN')}")
            for i, name in enumerate(base_names, 1):
                print(f"  {i}. {name}")
                
        # Obter domínios
        domains_input = input("\nEnter domain numbers (comma-separated) or domain names: ").strip()
        domains = []
        
        if domains_input:
            # Verificar se são números ou nomes
            if all(part.strip().isdigit() for part in domains_input.split(',')):
                # São números, converter para nomes
                for num in domains_input.split(','):
                    try:
                        idx = int(num.strip()) - 1
                        if 0 <= idx < len(base_names):
                            domains.append(base_names[idx])
                        else:
                            self.print_warning(f"Invalid domain number: {num}")
                    except ValueError:
                        self.print_warning(f"Invalid domain number: {num}")
            else:
                # São nomes, usar diretamente
                domains = [d.strip() for d in domains_input.split(',')]
                
        # Verificar se "General" está incluído
        if "General" not in domains:
            domains.append("General")
            self.print_info("Added 'General' domain (required).")
            
        # Obter flags de admin e trusted
        is_admin_input = input("Is admin? (y/n): ").strip().lower()
        is_admin = is_admin_input == 'y'
        
        is_trusted_input = input("Is trusted? (y/n): ").strip().lower()
        is_trusted = is_trusted_input == 'y'
        
        # Confirmar criação
        print(f"\n{self._colorize('User to be created:', 'CYAN')}")
        print(f"Username: {nome}")
        print(f"Level: {level}")
        print(f"Domains: {', '.join(domains)}")
        print(f"Admin: {'Yes' if is_admin else 'No'}")
        print(f"Trusted: {'Yes' if is_trusted else 'No'}")
        
        confirm = input("\nConfirm creation? (y/n): ").strip().lower()
        if confirm != 'y':
            self.print_info("User creation canceled.")
            return
            
        # Verificar se todos os campos obrigatórios estão presentes
        if not nome or not password or level is None or not domains:
            self.print_error("Missing required fields. User creation canceled.")
            return
            
        # Garantir que domains é uma lista de strings
        if not isinstance(domains, list):
            domains = [str(domains)]
        domains = [str(d) for d in domains]
            
        # Criar utilizador
        payload = {
            'nome': nome,
            'password': password,
            'level': level,
            'domains': domains,
            'is_admin': is_admin,
            'is_trusted': is_trusted
        }
        
        # Verificar payload antes de enviar
        self.print_info(f"Sending payload: {json.dumps(payload, indent=2)}")
        
        res = self.make_request('POST', '/api/users', data=payload)
        
        if res.get('success'):
            self.print_success(f"User '{nome}' created successfully.")
        else:
            self.print_error(res.get('error', 'Failed to create user.'))

    def delete_user(self):
        """Eliminar um utilizador (apenas admin)"""
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
            
        if not self.current_user.get('is_admin', False):
            self.print_error("Admin privileges required.")
            return
            
        # Listar utilizadores
        res = self.make_request('GET', '/api/users')
        
        if not res.get('success'):
            self.print_error(res.get('error', 'Failed to list users.'))
            return
            
        users = res.get('users', [])
        if not users:
            self.print_info("No users found.")
            return
            
        print(f"\n{self._colorize('Users:', 'CYAN')}")
        for i, user in enumerate(sorted(users, key=lambda x: x['nome']), 1):
            print(f"  {i}. {user['nome']} (Level: {user['level']}, Admin: {'Yes' if user.get('is_admin', False) else 'No'})")
            
        # Obter utilizador a eliminar
        user_input = input("\nEnter user number or username to delete: ").strip()
        nome = ""
        
        if user_input.isdigit():
            # É um número, converter para nome
            try:
                idx = int(user_input) - 1
                if 0 <= idx < len(users):
                    nome = sorted(users, key=lambda x: x['nome'])[idx]['nome']
                else:
                    self.print_error(f"Invalid user number: {user_input}")
                    return
            except ValueError:
                self.print_error(f"Invalid user number: {user_input}")
                return
        else:
            # É um nome, usar diretamente
            nome = user_input
            
        # Verificar se o utilizador existe
        if not any(u['nome'] == nome for u in users):
            self.print_error(f"User '{nome}' not found.")
            return
            
        # Verificar se está a tentar eliminar-se a si próprio
        if nome == self.current_user['nome']:
            self.print_error("You cannot delete yourself.")
            return
            
        # Confirmar eliminação
        confirm = input(f"Are you sure you want to delete user '{nome}'? (y/n): ").strip().lower()
        if confirm != 'y':
            self.print_info("User deletion canceled.")
            return
            
        # Eliminar utilizador
        res = self.make_request('DELETE', f'/api/users/{nome}')
        
        if res.get('success'):
            self.print_success(f"User '{nome}' deleted successfully.")
        else:
            self.print_error(res.get('error', 'Failed to delete user.'))

    def create_domain_config(self):
        """Criar uma configuração de domínio (apenas admin)"""
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
            
        if not self.current_user.get('is_admin', False):
            self.print_error("Admin privileges required.")
            return
            
        # Obter nome do domínio
        base_name = input("Enter domain base name: ").strip()
        if not base_name:
            self.print_error("Domain base name cannot be empty.")
            return
            
        # Listar níveis disponíveis
        res_levels = self.make_request('GET', '/api/levels')
        if not res_levels.get('success'):
            self.print_error(res_levels.get('error', 'Failed to get security levels.'))
            return
            
        levels = res_levels.get('levels', [])
        if not levels:
            self.print_error("No security levels configured.")
            return
            
        print(f"\n{self._colorize('Available Security Levels:', 'CYAN')}")
        for level in sorted(levels, key=lambda x: x['value']):
            print(f"  {level['value']}: {level['name']}")
            
        # Obter nível de segurança
        try:
            level = int(input("\nEnter security level: ").strip())
            # Verificar se o nível existe
            if not any(l['value'] == level for l in levels):
                self.print_warning(f"Level {level} not found in available levels. Proceeding anyway.")
        except ValueError:
            self.print_error("Invalid level format. Must be an integer.")
            return
            
        # Confirmar criação
        print(f"\n{self._colorize('Domain configuration to be created:', 'CYAN')}")
        print(f"Base name: {base_name}")
        print(f"Level: {level}")
        
        confirm = input("\nConfirm creation? (y/n): ").strip().lower()
        if confirm != 'y':
            self.print_info("Domain configuration creation canceled.")
            return
            
        # Criar configuração de domínio
        payload = {
            'base_name': base_name,
            'level': level
        }
        
        res = self.make_request('POST', '/api/domains/config', data=payload)
        
        if res.get('success'):
            self.print_success(f"Domain configuration '{base_name}' at level {level} created successfully.")
        else:
            self.print_error(res.get('error', 'Failed to create domain configuration.'))

    def delete_domain_config(self):
        """Eliminar uma configuração de domínio (apenas admin)"""
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
            
        if not self.current_user.get('is_admin', False):
            self.print_error("Admin privileges required.")
            return
            
        # Listar configurações de domínio
        res = self.make_request('GET', '/api/domains')
        
        if not res.get('success'):
            self.print_error(res.get('error', 'Failed to list domain configurations.'))
            return
            
        configs = res.get('domain_configurations', [])
        if not configs:
            self.print_info("No domain configurations found.")
            return
            
        print(f"\n{self._colorize('Domain Configurations:', 'CYAN')}")
        for i, config in enumerate(sorted(configs, key=lambda x: (x['name'], x['level'])), 1):
            print(f"  {i}. {config['name']} (Level: {config['level']})")
            
        # Obter configuração a eliminar
        config_input = input("\nEnter configuration number: ").strip()
        
        try:
            idx = int(config_input) - 1
            if 0 <= idx < len(configs):
                config = sorted(configs, key=lambda x: (x['name'], x['level']))[idx]
            else:
                self.print_error(f"Invalid configuration number: {config_input}")
                return
        except ValueError:
            self.print_error(f"Invalid configuration number: {config_input}")
            return
            
        # Confirmar eliminação
        print(f"\n{self._colorize('Domain configuration to be deleted:', 'CYAN')}")
        print(f"Base name: {config['name']}")
        print(f"Level: {config['level']}")
        
        confirm = input("\nConfirm deletion? (y/n): ").strip().lower()
        if confirm != 'y':
            self.print_info("Domain configuration deletion canceled.")
            return
            
        # Eliminar configuração de domínio
        payload = {
            'base_name': config['name'],
            'level': config['level']
        }
        
        res = self.make_request('DELETE', '/api/domains/config', data=payload)
        
        if res.get('success'):
            self.print_success(f"Domain configuration '{config['name']}' at level {config['level']} deleted successfully.")
        else:
            self.print_error(res.get('error', 'Failed to delete domain configuration.'))

    def admin_menu(self):
        """Menu de administração (apenas admin)"""
        if not self.authenticated:
            self.print_error("Not authenticated.")
            return
            
        if not self.current_user.get('is_admin', False):
            self.print_error("Admin privileges required.")
            return
            
        while True:
            print(f"\n{self._colorize('=== Admin Menu ===', 'CYAN BOLD')}")
            print("1. List Users")
            print("2. Create User")
            print("3. Delete User")
            print("4. List Domain Configurations")
            print("5. Create Domain Configuration")
            print("6. Delete Domain Configuration")
            print("0. Back to Main Menu")
            
            choice = input("\nEnter choice: ").strip()
            
            if choice == '1':
                self.list_users()
            elif choice == '2':
                self.create_user()
            elif choice == '3':
                self.delete_user()
            elif choice == '4':
                res = self.make_request('GET', '/api/domains')
                
                if res.get('success'):
                    configs = res.get('domain_configurations', [])
                    if not configs:
                        self.print_info("No domain configurations found.")
                    else:
                        print(f"\n{self._colorize('Domain Configurations:', 'CYAN')}")
                        print(f"{'Base Name':<20} {'Level':<10}")
                        print("-" * 30)
                        for config in sorted(configs, key=lambda x: (x['name'], x['level'])):
                            print(f"  {config['name']:<18} {config['level']:<10}")
                else:
                    self.print_error(res.get('error', 'Failed to list domain configurations.'))
            elif choice == '5':
                self.create_domain_config()
            elif choice == '6':
                self.delete_domain_config()
            elif choice == '0':
                return
            else:
                self.print_error("Invalid choice.")

    def interactive_menu(self):
        while True:
            if not self.authenticated:
                print("\n=== BLP Client ===")
                print("1. Login")
                print("0. Exit")
                
                choice = input("\nEnter choice: ").strip()
                
                if choice == '1':
                    self.login()
                elif choice == '0':
                    print("Exiting...")
                    break
                else:
                    self.print_error("Invalid choice.")
            else:
                is_admin = self.current_user.get('is_admin', False)
                admin_indicator = " (Admin)" if is_admin else ""
                
                print(f"\n=== BLP Client - Logged in as {self.current_user['nome']}{admin_indicator} ===")
                print("1. User Info")
                print("2. List Files")
                print("3. Retrieve File")
                print("4. Upload File")
                print("5. Append to File")
                print("6. Delete File")
                print("7. List Domains")
                print("8. List Security Levels")
                print("9. Configure Session Refresh")
                print("10. Manage Downloaded Files")
                
                # Mostrar opção de administração apenas para admins
                if is_admin:
                    print(f"{self._colorize('11. Admin Menu', 'CYAN BOLD')}")
                    
                print("12. Logout")
                print("0. Exit")
                
                choice = input("\nEnter choice: ").strip()
                
                if choice == '1':
                    self.print_user_info()
                elif choice == '2':
                    self.list_files()
                elif choice == '3':
                    filename = input("Enter filename to retrieve: ").strip()
                    save_option = input("Save to file? (y/n): ").strip().lower()
                    if save_option == 'y':
                        save_path = input("Enter save path: ").strip()
                        self.retrieve_file(filename, save_path)
                    else:
                        self.retrieve_file(filename)
                elif choice == '4':
                    self.upload_file_interactive()
                elif choice == '5':
                    self.append_file_interactive()
                elif choice == '6':
                    filename = input("Enter filename to delete: ").strip()
                    self.delete_file(filename)
                elif choice == '7':
                    self.list_domains()
                elif choice == '8':
                    self.list_levels()
                elif choice == '9':
                    self.configure_session_refresh()
                elif choice == '10':
                    self.manage_downloaded_files()
                elif choice == '11' and is_admin:
                    self.admin_menu()
                elif choice == '12':
                    self.logout()
                elif choice == '0':
                    if self.authenticated:
                        self.logout()
                    print("Exiting...")
                    break
                else:
                    self.print_error("Invalid choice.")

def main():
    parser = argparse.ArgumentParser(description="BLP Client")
    parser.add_argument("--server", default="https://localhost:5001", help="Server URL")
    parser.add_argument("--ca-cert", help="Path to CA certificate")
    parser.add_argument("--client-cert", help="Path to client certificate")
    parser.add_argument("--client-key", help="Path to client private key")
    parser.add_argument("--username", help="Username for login")
    parser.add_argument("--password", help="Password for login")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--refresh-interval", type=int, default=600, help="Session refresh interval in seconds")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Configurar certificados
    ca_cert = args.ca_cert
    client_cert = args.client_cert
    client_key = args.client_key
    
    # Se --no-verify foi especificado, não usar CA cert
    if args.no_verify:
        ca_cert = None
    
    # Inicializar cliente
    client = BLPClient(
        server_url=args.server,
        ca_cert=ca_cert,
        client_cert=client_cert,
        client_key=client_key,
        session_refresh_interval=args.refresh_interval,
        verbose=args.verbose
    )
    
    # Login automático se fornecido username e password
    if args.username and args.password:
        client.login(args.username, args.password)
    
    # Iniciar menu interativo
    try:
        client.interactive_menu()
    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting...")
    except Exception as e:
        client.print_error(f"Unexpected error: {e}")
    finally:
        if client.authenticated:
            client.logout()

if __name__ == "__main__":
    main()
