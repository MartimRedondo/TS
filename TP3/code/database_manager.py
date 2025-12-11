import hashlib
import os
from typing import Optional, List, Dict, Any
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from cryptography.fernet import Fernet
import json

# Classe personalizada para armazenamento JSON com indentação
class PrettyJSONStorage(JSONStorage):
    """
    Armazenamento JSON com indentação para melhor legibilidade.
    Estende a classe JSONStorage do TinyDB para adicionar formatação ao ficheiro JSON.
    """
    def __init__(self, path, **kwargs):
        # Definir a indentação padrão como 2 espaços
        self.indent = kwargs.pop('indent', 2)
        super().__init__(path, **kwargs)

    def write(self, data):
        # Sobrescrever o método write para adicionar indentação
        with open(self._handle.name, 'w') as f:
            json.dump(data, f, indent=self.indent)

COMMON_DOMAIN_BASE_NAME = "General"

class DatabaseManager:
    def __init__(self, db_path: str = "blp_database.json", encryption_key: Optional[bytes] = None):
        # Usar o armazenamento personalizado com indentação
        self.db = TinyDB(db_path, storage=PrettyJSONStorage)
        self.users_table = self.db.table('users')
        self.files_table = self.db.table('files') # Stores file with base_domain_name and file_level
        self.levels_table = self.db.table('levels')
        self.domains_table = self.db.table('domains_config') # Stores {'name': base_name, 'level': int} pairs

        if encryption_key is None:
            self.encryption_key = Fernet.generate_key()
        else:
            self.encryption_key = encryption_key
        self.cipher = Fernet(self.encryption_key)

    def _hash_password(self, password: str) -> str:
        salt = os.urandom(32)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt.hex() + pwdhash.hex()

    def _verify_password(self, stored_password: str, provided_password: str) -> bool:
        salt = bytes.fromhex(stored_password[:64])
        stored_hash = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return pwdhash.hex() == stored_hash

    # LEVEL MANAGEMENT
    def create_level(self, value: int, name: str) -> bool:
        Level = Query()
        if self.levels_table.search(Level.value == value): return False
        self.levels_table.insert({'value': value, 'name': name})
        return True

    def get_level(self, value: int) -> Optional[Dict[str, Any]]:
        Level = Query()
        levels = self.levels_table.search(Level.value == value)
        return levels[0] if levels else None

    def list_levels(self) -> List[Dict[str, Any]]:
        return sorted(self.levels_table.all(), key=lambda x: x['value'])
    
    def delete_level(self, value: int) -> bool:
        DomainConfig = Query()
        if self.domains_table.search(DomainConfig.level == value):
            raise ValueError(f"Cannot delete level {value}: domain configurations exist for it.")
        User = Query()
        if self.users_table.search(User.level == value):
            raise ValueError(f"Cannot delete level {value}: users are assigned to it.")
        File = Query() 
        if self.files_table.search(File.level == value):
            raise ValueError(f"Cannot delete level {value}: files are classified at this level.")
        Level = Query()
        removed = self.levels_table.remove(Level.value == value)
        return len(removed) > 0

    # DOMAIN CONFIGURATION MANAGEMENT
    def create_domain_config(self, base_name: str, level: int) -> bool:
        if not self.get_level(level):
            raise ValueError(f"Level {level} does not exist. Cannot configure domain '{base_name}'.")
        
        DomainConfig = Query()
        if self.domains_table.search((DomainConfig.name == base_name) & (DomainConfig.level == level)):
            return False
        
        self.domains_table.insert({'name': base_name, 'level': level})
        return True

    def get_domain_config(self, base_name: str, level: int) -> Optional[Dict[str, Any]]:
        DomainConfig = Query()
        configs = self.domains_table.search((DomainConfig.name == base_name) & (DomainConfig.level == level))
        return configs[0] if configs else None

    def list_domain_configs(self, level_filter: Optional[int] = None) -> List[Dict[str, Any]]:
        if level_filter is not None:
            DomainConfig = Query()
            return self.domains_table.search(DomainConfig.level == level_filter)
        return self.domains_table.all()

    def list_base_domain_names(self) -> List[str]:
        return sorted(list(set(d['name'] for d in self.domains_table.all())))

    def delete_domain_config(self, base_name: str, level: int) -> bool:
        File = Query()
        if self.files_table.search((File.domain == base_name) & (File.level == level)):
            raise ValueError(f"Cannot delete domain config '{base_name}' at level {level}: files exist in it.")
        
        User = Query()
        for user_doc in self.users_table.search(User.level == level):
            if base_name in user_doc.get('domains', []):
                 raise ValueError(f"Cannot delete domain config '{base_name}' at level {level}: user '{user_doc['nome']}' relies on it.")

        DomainConfig = Query()
        removed = self.domains_table.remove((DomainConfig.name == base_name) & (DomainConfig.level == level))
        return len(removed) > 0

    # USER MANAGEMENT
    def create_user(self, nome: str, password: str, level: int,
                   assigned_base_domains: List[str],
                   is_admin: bool = False, is_trusted: bool = False) -> bool:
        User = Query()
        if self.users_table.search(User.nome == nome): return False
        if not self.get_level(level):
            raise ValueError(f"User's security level {level} does not exist.")

        user_s_base_domains = set(assigned_base_domains)
        user_s_base_domains.add(COMMON_DOMAIN_BASE_NAME) 

        for base_name in user_s_base_domains:
            if not self.get_domain_config(base_name, level): # A domain must be configured for the user's level to be assigned
                # Attempt to configure the common domain automatically if it's missing for this level
                if base_name == COMMON_DOMAIN_BASE_NAME:
                    self.create_domain_config(COMMON_DOMAIN_BASE_NAME, level)
                else:
                    raise ValueError(f"Domain '{base_name}' is not configured for level {level}. User cannot be assigned.")
        
        self.users_table.insert({
            'nome': nome, 'hashed_password': self._hash_password(password), 'level': level,
            'domains': sorted(list(user_s_base_domains)), 
            'is_admin': is_admin, 'is_trusted': is_trusted
        })
        return True

    def delete_user(self, nome: str) -> bool:
        UserQ = Query()
        user_to_delete = self.users_table.get(UserQ.nome == nome)
        if not user_to_delete:
            return False # User not found

        # Prevent deletion of the only admin user
        if user_to_delete.get('is_admin', False):
            admin_users = self.users_table.search(UserQ.is_admin == True)
            if len(admin_users) <= 1:
                # Cannot delete the last admin
                raise ValueError("Cannot delete the last admin user.")
        
        removed_count = self.users_table.remove(UserQ.nome == nome)
        return removed_count > 0

    def update_user(self, nome: str, level: Optional[int] = None,
                   assigned_base_domains: Optional[List[str]] = None,
                   is_admin: Optional[bool] = None, is_trusted: Optional[bool] = None) -> bool:
        UserQ = Query()
        user_doc = self.users_table.get(UserQ.nome == nome)
        if not user_doc: return False

        final_level = level if level is not None else user_doc['level']
        if level is not None and not self.get_level(final_level):
            raise ValueError(f"User's new security level {final_level} does not exist.")

        current_base_domains = set(user_doc['domains'])
        if assigned_base_domains is not None:
            final_base_domains = set(assigned_base_domains)
        else:
            final_base_domains = current_base_domains
        
        final_base_domains.add(COMMON_DOMAIN_BASE_NAME) 

        for base_name in final_base_domains:
            if not self.get_domain_config(base_name, final_level):
                 # Attempt to configure the common domain automatically if it's missing for this level
                if base_name == COMMON_DOMAIN_BASE_NAME:
                    self.create_domain_config(COMMON_DOMAIN_BASE_NAME, final_level)
                else:
                    raise ValueError(f"Domain '{base_name}' is not configured for user's target level {final_level}.")


        update_data = {}
        if level is not None: update_data['level'] = final_level
        # Update domains if new ones are provided OR if level changed (domain validity might change)
        if assigned_base_domains is not None or (level is not None and level != user_doc['level']):
            update_data['domains'] = sorted(list(final_base_domains))
        if is_admin is not None: update_data['is_admin'] = is_admin
        if is_trusted is not None: update_data['is_trusted'] = is_trusted

        if update_data:
            # If is_admin is being set to False, ensure there's at least one other admin
            if 'is_admin' in update_data and not update_data['is_admin'] and user_doc.get('is_admin'):
                admin_users = self.users_table.search(UserQ.is_admin == True)
                if len(admin_users) <= 1:
                    raise ValueError("Cannot remove admin status from the last admin user.")
            return len(self.users_table.update(update_data, UserQ.nome == nome)) > 0
        return False # No changes made


    def authenticate_user(self, nome: str, password: str) -> Optional[Dict[str, Any]]:
        user_doc = self.users_table.get(Query().nome == nome)
        if user_doc and self._verify_password(user_doc['hashed_password'], password):
            return {k: v for k, v in user_doc.items() if k != 'hashed_password'}
        return None

    def get_user(self, nome: str) -> Optional[Dict[str, Any]]:
        user_doc = self.users_table.get(Query().nome == nome)
        if user_doc:
            return {k: v for k, v in user_doc.items() if k != 'hashed_password'}
        return None

    def list_users(self) -> List[Dict[str, Any]]:
        return [{k:v for k,v in u.items() if k != 'hashed_password'} for u in self.users_table.all()]

    # FILE MANAGEMENT
    def store_file(self, filename: str, base_domain_name: str, file_level: int, content: bytes) -> bool:
        if not self.get_domain_config(base_domain_name, file_level):
            raise ValueError(f"Domain '{base_domain_name}' is not configured for level {file_level}. Cannot store file.")
        
        File = Query()
        if self.files_table.search(File.filename == filename):
            return False 
        
        encrypted_content = self.cipher.encrypt(content)
        self.files_table.insert({
            'filename': filename,
            'domain': base_domain_name, 
            'level': file_level,       
            'encrypted_content': encrypted_content.decode('utf-8')
        })
        return True

    def retrieve_file(self, filename: str, user_nome: str) -> Optional[bytes]:
        user = self.get_user(user_nome)
        if not user: return None
        
        file_doc = self.files_table.get(Query().filename == filename)
        if not file_doc: return None
        
        if not self._check_file_read_access(file_doc, user): return None
        
        return self.cipher.decrypt(file_doc['encrypted_content'].encode('utf-8'))

    def write_file(self, filename: str, base_domain_name: str, file_level: int, 
                   content: bytes, user_nome: str) -> bool:
        user = self.get_user(user_nome)
        if not user: return False
        
        target_domain_config = self.get_domain_config(base_domain_name, file_level)
        if not target_domain_config:
            raise ValueError(f"Domain '{base_domain_name}' is not configured for level {file_level}. Cannot write file.")

        if not self._check_file_write_access(base_domain_name, file_level, user):
            return False
        
        self.files_table.remove(Query().filename == filename) 
        return self.store_file(filename, base_domain_name, file_level, content)

    def list_accessible_files(self, user_nome: str) -> List[Dict[str, Any]]:
        user = self.get_user(user_nome)
        if not user: return []
        accessible_files = []
        for file_data in self.files_table.all():
            if self._check_file_read_access(file_data, user):
                accessible_files.append({
                    'filename': file_data['filename'],
                    'domain': file_data['domain'], 
                    'level': file_data['level']
                })
        return accessible_files
    
    def get_file_info(self, filename: str) -> Optional[Dict[str, Any]]:
        file_doc = self.files_table.get(Query().filename == filename)
        if file_doc:
            return {key: file_doc[key] for key in ['filename', 'domain', 'level']}
        return None
    
    def delete_file_by_filename(self, filename: str) -> bool:
        File = Query()
        removed_docs = self.files_table.remove(File.filename == filename)
        return len(removed_docs) > 0

    # ACCESS CONTROL HELPERS
    def _check_file_read_access(self, file_data: Dict[str, Any], user: Dict[str, Any]) -> bool:
        user_level = user['level']
        file_level = file_data['level']
        file_base_domain = file_data['domain'] 
        user_assigned_base_domains = user.get('domains', [])

        if user_level > file_level:
            return False
        
        if file_base_domain in user_assigned_base_domains:
            return True
            
        return False

    def _check_file_write_access(self, target_base_domain: str, target_domain_level: int,
                                 user: Dict[str, Any]) -> bool:
        user_level = user['level']
        user_assigned_base_domains = user.get('domains', [])
        is_user_admin = user.get('is_admin', False)
        is_user_trusted = user.get('is_trusted', False)

        if target_base_domain not in user_assigned_base_domains:
            return False

        if is_user_admin:
            return True

        if is_user_trusted:
            return True

        if user_level == target_domain_level:
            return True
        
        return False
            
    def get_encryption_key(self) -> bytes:
        return self.encryption_key

    def close(self):
        self.db.close()