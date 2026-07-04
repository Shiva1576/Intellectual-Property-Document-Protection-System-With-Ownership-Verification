import os
from tinydb import TinyDB, Query
from datetime import datetime
from crypto_utils import generate_ecc_keypair, encrypt_private_key, decrypt_private_key

DB_PATH = 'data'
if not os.path.exists(DB_PATH):
    os.makedirs(DB_PATH)

db = TinyDB(os.path.join(DB_PATH, 'ip_system.json'))

users_table = db.table('users')
ip_documents_table = db.table('ip_documents')
files_table = db.table('files')
shared_secrets_table = db.table('shared_secrets')
messages_table = db.table('messages')
ownership_table = db.table('ownership')
activity_log_table = db.table('activity_log')

User = Query()
IPDocument = Query()
File = Query()
SharedSecret = Query()
Message = Query()
Ownership = Query()
ActivityLog = Query()

SYSTEM_KEYS_FILE = os.path.join(DB_PATH, 'system_keys.json')
SYSTEM_KEY_PASSWORD = os.environ.get('SESSION_SECRET', 'ip-protection-system-key-2024')

def get_system_keys():
    if os.path.exists(SYSTEM_KEYS_FILE):
        import json
        with open(SYSTEM_KEYS_FILE, 'r') as f:
            return json.load(f)
    else:
        private_key, public_key = generate_ecc_keypair()
        keys = {'private_key': private_key, 'public_key': public_key, 'encrypted': False}
        import json
        with open(SYSTEM_KEYS_FILE, 'w') as f:
            json.dump(keys, f)
        return keys


def create_user(username, password_hash, email, full_name, role, organization, phone, address, password=None):
    private_key, public_key = generate_ecc_keypair()
    user_data = {
        'username': username,
        'password_hash': password_hash,
        'email': email,
        'full_name': full_name,
        'role': role,
        'organization': organization,
        'phone': phone,
        'address': address,
        'private_key': private_key,
        'public_key': public_key,
        'key_encrypted': False,
        'created_at': datetime.now().isoformat(),
        'is_active': True
    }
    users_table.insert(user_data)
    return user_data


def get_user_by_username(username):
    result = users_table.search(User.username == username)
    return result[0] if result else None


def get_user_by_id(doc_id):
    return users_table.get(doc_id=doc_id)


def update_user(username, updates):
    users_table.update(updates, User.username == username)


def get_users_by_role(role):
    return users_table.search(User.role == role)


def create_ip_document(title, description, creator_username, document_type, keywords):
    doc_data = {
        'title': title,
        'description': description,
        'creator_username': creator_username,
        'document_type': document_type,
        'keywords': keywords,
        'status': 'draft',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat(),
        'registrar_username': None,
        'owner_username': None,
        'registration_number': None
    }
    doc_id = ip_documents_table.insert(doc_data)
    return doc_id, doc_data


def get_ip_documents_by_creator(creator_username):
    return ip_documents_table.search(IPDocument.creator_username == creator_username)


def get_ip_documents_by_status(status):
    return ip_documents_table.search(IPDocument.status == status)


def get_ip_documents_by_registrar(registrar_username):
    return ip_documents_table.search(IPDocument.registrar_username == registrar_username)


def get_ip_documents_by_owner(owner_username):
    return ip_documents_table.search(IPDocument.owner_username == owner_username)


def get_ip_document_by_id(doc_id):
    return ip_documents_table.get(doc_id=doc_id)


def update_ip_document(doc_id, updates):
    updates['updated_at'] = datetime.now().isoformat()
    ip_documents_table.update(updates, doc_ids=[doc_id])


def create_file_record(original_filename, encrypted_filename, ip_document_id, uploader_username, file_size):
    file_data = {
        'original_filename': original_filename,
        'encrypted_filename': encrypted_filename,
        'ip_document_id': ip_document_id,
        'uploader_username': uploader_username,
        'file_size': file_size,
        'uploaded_at': datetime.now().isoformat(),
        'is_encrypted': True
    }
    file_id = files_table.insert(file_data)
    return file_id, file_data


def get_files_by_document(ip_document_id):
    return files_table.search(File.ip_document_id == ip_document_id)


def get_file_by_id(file_id):
    return files_table.get(doc_id=file_id)


def create_shared_secret(from_username, to_username, secret_data, description):
    secret = {
        'from_username': from_username,
        'to_username': to_username,
        'secret_data': secret_data,
        'description': description,
        'created_at': datetime.now().isoformat(),
        'is_read': False
    }
    secret_id = shared_secrets_table.insert(secret)
    return secret_id, secret


def get_shared_secrets_for_user(username):
    return shared_secrets_table.search(SharedSecret.to_username == username)


def get_shared_secrets_by_user(username):
    return shared_secrets_table.search(SharedSecret.from_username == username)


def mark_secret_as_read(secret_id):
    shared_secrets_table.update({'is_read': True}, doc_ids=[secret_id])


def create_message(from_username, to_username, subject, content, related_document_id=None):
    message = {
        'from_username': from_username,
        'to_username': to_username,
        'subject': subject,
        'content': content,
        'related_document_id': related_document_id,
        'created_at': datetime.now().isoformat(),
        'is_read': False
    }
    msg_id = messages_table.insert(message)
    return msg_id, message


def get_messages_for_user(username):
    return messages_table.search(Message.to_username == username)


def get_messages_by_user(username):
    return messages_table.search(Message.from_username == username)


def mark_message_as_read(msg_id):
    messages_table.update({'is_read': True}, doc_ids=[msg_id])


def create_ownership_record(ip_document_id, owner_username, previous_owner=None, transfer_reason=None):
    record = {
        'ip_document_id': ip_document_id,
        'owner_username': owner_username,
        'previous_owner': previous_owner,
        'transfer_reason': transfer_reason,
        'transferred_at': datetime.now().isoformat()
    }
    record_id = ownership_table.insert(record)
    return record_id, record


def get_ownership_history(ip_document_id):
    return ownership_table.search(Ownership.ip_document_id == ip_document_id)


def log_activity(username, action, details, ip_document_id=None):
    log = {
        'username': username,
        'action': action,
        'details': details,
        'ip_document_id': ip_document_id,
        'timestamp': datetime.now().isoformat()
    }
    activity_log_table.insert(log)


def get_activity_log_for_user(username):
    return activity_log_table.search(ActivityLog.username == username)


def get_activity_log_for_document(ip_document_id):
    return activity_log_table.search(ActivityLog.ip_document_id == ip_document_id)


def get_all_ip_documents():
    return ip_documents_table.all()


def get_decrypted_system_key():
    keys = get_system_keys()
    if keys.get('encrypted', False):
        return decrypt_private_key(keys['private_key'], SYSTEM_KEY_PASSWORD)
    return keys['private_key']


def get_user_private_key(username):
    user = get_user_by_username(username)
    if not user:
        return None
    return user['private_key']
