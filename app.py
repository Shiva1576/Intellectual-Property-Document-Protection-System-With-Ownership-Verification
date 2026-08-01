import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import base64
from datetime import datetime
\
import io

from database import (
    create_user, get_user_by_username, update_user, get_users_by_role,
    create_ip_document, get_ip_documents_by_creator, get_ip_documents_by_status,
    get_ip_documents_by_registrar, get_ip_documents_by_owner, get_ip_document_by_id,
    update_ip_document, create_file_record, get_files_by_document, get_file_by_id,
    create_shared_secret, get_shared_secrets_for_user, get_shared_secrets_by_user,
    mark_secret_as_read, create_message, get_messages_for_user, get_messages_by_user,
    mark_message_as_read, create_ownership_record, get_ownership_history,
    log_activity, get_activity_log_for_user, get_activity_log_for_document,
    get_all_ip_documents, get_system_keys, get_decrypted_system_key
)
from crypto_utils import encrypt_file, decrypt_file, sign_data, verify_signature

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'ip-protection-secret-key-2024')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('Please login to access this page.', 'warning')
                return redirect(url_for('login'))
            if session.get('role') != role:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        role = request.form.get('role')
        organization = request.form.get('organization')
        phone = request.form.get('phone')
        address = request.form.get('address')
        
        if not all([username, password, email, full_name, role]):
            flash('Please fill in all required fields.', 'danger')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')
        
        if get_user_by_username(username):
            flash('Username already exists.', 'danger')
            return render_template('signup.html')
        
        password_hash = generate_password_hash(password)
        create_user(username, password_hash, email, full_name, role, organization, phone, address)
        
        log_activity(username, 'signup', f'New {role} account created')
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = get_user_by_username(username)
        
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            log_activity(username, 'login', 'User logged in')
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'username' in session:
        log_activity(session['username'], 'logout', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    role = session.get('role')
    if role == 'ip_generator':
        return redirect(url_for('ip_generator_dashboard'))
    elif role == 'patent_registrar':
        return redirect(url_for('registrar_dashboard'))
    elif role == 'patent_owner':
        return redirect(url_for('owner_dashboard'))
    return render_template('dashboard.html')


@app.route('/ip-generator')
@role_required('ip_generator')
def ip_generator_dashboard():
    documents = get_ip_documents_by_creator(session['username'])
    return render_template('ip_generator/dashboard.html', documents=documents)


@app.route('/ip-generator/create', methods=['GET', 'POST'])
@role_required('ip_generator')
def ip_create_document():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        document_type = request.form.get('document_type')
        keywords = request.form.get('keywords')
        
        doc_id, doc_data = create_ip_document(
            title, description, session['username'], document_type, keywords
        )
        log_activity(session['username'], 'create_document', f'Created IP document: {title}', doc_id)
        flash('IP Document created successfully!', 'success')
        return redirect(url_for('ip_generator_dashboard'))
    
    return render_template('ip_generator/create_document.html')


@app.route('/ip-generator/upload/<int:doc_id>', methods=['GET', 'POST'])
@role_required('ip_generator')
def ip_upload_files(doc_id):
    document = get_ip_document_by_id(doc_id)
    if not document or document['creator_username'] != session['username']:
        flash('Document not found or access denied.', 'danger')
        return redirect(url_for('ip_generator_dashboard'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_data = file.read()
            
            user = get_user_by_username(session['username'])
            system_keys = get_system_keys()
            
            encrypted_data = encrypt_file(file_data, user['private_key'], system_keys['public_key'])
            
            encrypted_filename = f"enc_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            with open(encrypted_path, 'w') as f:
                f.write(encrypted_data)
            
            create_file_record(filename, encrypted_filename, doc_id, session['username'], len(file_data))
            log_activity(session['username'], 'upload_file', f'Uploaded encrypted file: {filename}', doc_id)
            
            flash('File uploaded and encrypted successfully!', 'success')
            return redirect(url_for('ip_view_submissions'))
    
    files = get_files_by_document(doc_id)
    return render_template('ip_generator/upload_files.html', document=document, files=files, doc_id=doc_id)


@app.route('/ip-generator/share/<int:doc_id>', methods=['GET', 'POST'])
@role_required('ip_generator')
def ip_share_with_registrar(doc_id):
    document = get_ip_document_by_id(doc_id)
    if not document or document['creator_username'] != session['username']:
        flash('Document not found or access denied.', 'danger')
        return redirect(url_for('ip_generator_dashboard'))
    
    registrars = get_users_by_role('patent_registrar')
    
    if request.method == 'POST':
        registrar_username = request.form.get('registrar')
        secret_info = request.form.get('secret_info')
        message_content = request.form.get('message')
        
        update_ip_document(doc_id, {'status': 'submitted', 'registrar_username': registrar_username})
        
        if secret_info:
            user = get_user_by_username(session['username'])
            registrar = get_user_by_username(registrar_username)
            encrypted_secret = encrypt_file(secret_info.encode(), user['private_key'], registrar['public_key'])
            create_shared_secret(session['username'], registrar_username, encrypted_secret, f'Secret for document: {document["title"]}')
        
        if message_content:
            create_message(session['username'], registrar_username, f'IP Document Submission: {document["title"]}', message_content, doc_id)
        
        log_activity(session['username'], 'share_document', f'Shared document with registrar: {registrar_username}', doc_id)
        flash('Document shared with registrar successfully!', 'success')
        return redirect(url_for('ip_generator_dashboard'))
    
    return render_template('ip_generator/share_registrar.html', document=document, registrars=registrars, doc_id=doc_id)


@app.route('/ip-generator/submissions')
@role_required('ip_generator')
def ip_view_submissions():
    documents = get_ip_documents_by_creator(session['username'])
    documents_with_files = []
    for doc in documents:
        doc_copy = dict(doc)
        doc_copy['files'] = get_files_by_document(doc.doc_id)
        doc_copy['doc_id'] = doc.doc_id
        documents_with_files.append(doc_copy)
    return render_template('ip_generator/view_submissions.html', documents=documents_with_files)


@app.route('/ip-generator/profile', methods=['GET', 'POST'])
@role_required('ip_generator')
def ip_manage_profile():
    user = get_user_by_username(session['username'])
    
    if request.method == 'POST':
        updates = {
            'email': request.form.get('email'),
            'full_name': request.form.get('full_name'),
            'organization': request.form.get('organization'),
            'phone': request.form.get('phone'),
            'address': request.form.get('address')
        }
        update_user(session['username'], updates)
        session['full_name'] = updates['full_name']
        log_activity(session['username'], 'update_profile', 'Profile updated')
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('ip_manage_profile'))
    
    return render_template('ip_generator/manage_profile.html', user=user)


@app.route('/registrar')
@role_required('patent_registrar')
def registrar_dashboard():
    submitted_docs = get_ip_documents_by_status('submitted')
    my_docs = get_ip_documents_by_registrar(session['username'])
    return render_template('registrar/dashboard.html', submitted_docs=submitted_docs, my_docs=my_docs)


@app.route('/registrar/review/<int:doc_id>', methods=['GET', 'POST'])
@role_required('patent_registrar')
def registrar_review(doc_id):
    document = get_ip_document_by_id(doc_id)
    if not document:
        flash('Document not found.', 'danger')
        return redirect(url_for('registrar_dashboard'))
    
    files = get_files_by_document(doc_id)
    creator = get_user_by_username(document['creator_username'])
    
    if request.method == 'POST':
        action = request.form.get('action')
        comments = request.form.get('comments')
        
        if action == 'approve':
            reg_number = f"PAT-{datetime.now().strftime('%Y%m%d')}-{doc_id:04d}"
            update_ip_document(doc_id, {
                'status': 'approved',
                'registrar_username': session['username'],
                'registration_number': reg_number
            })
            log_activity(session['username'], 'approve_document', f'Approved document with reg number: {reg_number}', doc_id)
            flash(f'Document approved! Registration Number: {reg_number}', 'success')
        elif action == 'reject':
            update_ip_document(doc_id, {'status': 'rejected', 'registrar_username': session['username']})
            log_activity(session['username'], 'reject_document', 'Document rejected', doc_id)
            flash('Document rejected.', 'warning')
        
        if comments:
            create_message(session['username'], document['creator_username'], f'Review Comments: {document["title"]}', comments, doc_id)
        
        return redirect(url_for('registrar_dashboard'))
    
    return render_template('registrar/review.html', document=document, files=files, creator=creator, doc_id=doc_id)


@app.route('/registrar/download-encrypted/<int:file_id>')
@role_required('patent_registrar')
def registrar_download_encrypted(file_id):
    file_record = get_file_by_id(file_id)
    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('registrar_dashboard'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['encrypted_filename'])
    
    if os.path.exists(file_path):
        log_activity(session['username'], 'download_encrypted', f'Downloaded encrypted file: {file_record["original_filename"]}')
        return send_file(file_path, as_attachment=True, download_name=f"encrypted_{file_record['original_filename']}.enc")
    
    flash('File not found on server.', 'danger')
    return redirect(url_for('registrar_dashboard'))


@app.route('/registrar/verify/<int:doc_id>')
@role_required('patent_registrar')
def registrar_verify_ownership(doc_id):
    document = get_ip_document_by_id(doc_id)
    if not document:
        flash('Document not found.', 'danger')
        return redirect(url_for('registrar_dashboard'))
    
    ownership_history = get_ownership_history(doc_id)
    creator = get_user_by_username(document['creator_username'])
    owner = get_user_by_username(document['owner_username']) if document['owner_username'] else None
    
    return render_template('registrar/verify_ownership.html', document=document, 
                         ownership_history=ownership_history, creator=creator, owner=owner, doc_id=doc_id)


@app.route('/registrar/registry')
@role_required('patent_registrar')
def registrar_manage_registry():
    all_docs = get_all_ip_documents()
    docs_with_info = []
    for doc in all_docs:
        doc_copy = dict(doc)
        doc_copy['doc_id'] = doc.doc_id
        doc_copy['creator'] = get_user_by_username(doc['creator_username'])
        docs_with_info.append(doc_copy)
    return render_template('registrar/manage_registry.html', documents=docs_with_info)


@app.route('/registrar/communications')
@role_required('patent_registrar')
def registrar_communications():
    received_messages = get_messages_for_user(session['username'])
    sent_messages = get_messages_by_user(session['username'])
    secrets = get_shared_secrets_for_user(session['username'])
    return render_template('registrar/communications.html', 
                         received_messages=received_messages, 
                         sent_messages=sent_messages, secrets=secrets)


@app.route('/owner')
@role_required('patent_owner')
def owner_dashboard():
    owned_docs = get_ip_documents_by_owner(session['username'])
    approved_docs = [d for d in get_ip_documents_by_status('approved') if d.get('owner_username') is None]
    return render_template('owner/dashboard.html', owned_docs=owned_docs, approved_docs=approved_docs)


@app.route('/owner/claim/<int:doc_id>', methods=['POST'])
@role_required('patent_owner')
def owner_claim_patent(doc_id):
    document = get_ip_document_by_id(doc_id)
    if not document or document['status'] != 'approved':
        flash('Cannot claim this patent.', 'danger')
        return redirect(url_for('owner_dashboard'))
    
    update_ip_document(doc_id, {'owner_username': session['username']})
    create_ownership_record(doc_id, session['username'], None, 'Initial ownership claim')
    log_activity(session['username'], 'claim_ownership', f'Claimed ownership of patent', doc_id)
    
    flash('Patent ownership claimed successfully!', 'success')
    return redirect(url_for('owner_dashboard'))


@app.route('/owner/patents')
@role_required('patent_owner')
def owner_view_patents():
    owned_docs = get_ip_documents_by_owner(session['username'])
    docs_with_files = []
    for doc in owned_docs:
        doc_copy = dict(doc)
        doc_copy['files'] = get_files_by_document(doc.doc_id)
        doc_copy['doc_id'] = doc.doc_id
        docs_with_files.append(doc_copy)
    return render_template('owner/view_patents.html', documents=docs_with_files)


@app.route('/owner/download-encrypted/<int:file_id>')
@role_required('patent_owner')
def owner_download_encrypted(file_id):
    file_record = get_file_by_id(file_id)
    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('owner_view_patents'))
    
    document = get_ip_document_by_id(file_record['ip_document_id'])
    if document['owner_username'] != session['username']:
        flash('Access denied.', 'danger')
        return redirect(url_for('owner_view_patents'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['encrypted_filename'])
    
    if os.path.exists(file_path):
        log_activity(session['username'], 'download_encrypted', f'Downloaded encrypted file: {file_record["original_filename"]}')
        return send_file(file_path, as_attachment=True, download_name=f"encrypted_{file_record['original_filename']}.enc")
    
    flash('File not found on server.', 'danger')
    return redirect(url_for('owner_view_patents'))


@app.route('/owner/download-decrypted/<int:file_id>')
@role_required('patent_owner')
def owner_download_decrypted(file_id):
    file_record = get_file_by_id(file_id)
    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('owner_view_patents'))
    
    document = get_ip_document_by_id(file_record['ip_document_id'])
    if document['owner_username'] != session['username']:
        flash('Access denied.', 'danger')
        return redirect(url_for('owner_view_patents'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['encrypted_filename'])
    
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            encrypted_data = f.read()
        
        uploader = get_user_by_username(file_record['uploader_username'])
        system_private_key = get_decrypted_system_key()
        
        try:
            decrypted_data = decrypt_file(encrypted_data, system_private_key, uploader['public_key'])
            log_activity(session['username'], 'download_decrypted', f'Downloaded decrypted file: {file_record["original_filename"]}')
            
            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=file_record['original_filename']
            )
        except Exception as e:
            flash('Error decrypting file.', 'danger')
            return redirect(url_for('owner_view_patents'))
    
    flash('File not found on server.', 'danger')
    return redirect(url_for('owner_view_patents'))


@app.route('/owner/transfer/<int:doc_id>', methods=['GET', 'POST'])
@role_required('patent_owner')
def owner_transfer_ownership(doc_id):
    document = get_ip_document_by_id(doc_id)
    if not document or document['owner_username'] != session['username']:
        flash('Access denied.', 'danger')
        return redirect(url_for('owner_dashboard'))
    
    other_owners = [u for u in get_users_by_role('patent_owner') if u['username'] != session['username']]
    
    if request.method == 'POST':
        new_owner = request.form.get('new_owner')
        reason = request.form.get('reason')
        
        update_ip_document(doc_id, {'owner_username': new_owner})
        create_ownership_record(doc_id, new_owner, session['username'], reason)
        log_activity(session['username'], 'transfer_ownership', f'Transferred ownership to {new_owner}', doc_id)
        
        create_message(session['username'], new_owner, f'Ownership Transfer: {document["title"]}', 
                      f'Ownership of "{document["title"]}" has been transferred to you. Reason: {reason}', doc_id)
        
        flash('Ownership transferred successfully!', 'success')
        return redirect(url_for('owner_dashboard'))
    
    return render_template('owner/transfer_ownership.html', document=document, other_owners=other_owners, doc_id=doc_id)


@app.route('/owner/history/<int:doc_id>')
@role_required('patent_owner')
def owner_document_history(doc_id):
    document = get_ip_document_by_id(doc_id)
    if not document or document['owner_username'] != session['username']:
        flash('Access denied.', 'danger')
        return redirect(url_for('owner_dashboard'))
    
    ownership_history = get_ownership_history(doc_id)
    activity_log = get_activity_log_for_document(doc_id)
    
    return render_template('owner/document_history.html', document=document, 
                         ownership_history=ownership_history, activity_log=activity_log, doc_id=doc_id)


@app.route('/owner/secrets')
@role_required('patent_owner')
def owner_secrets():
    secrets = get_shared_secrets_for_user(session['username'])
    messages = get_messages_for_user(session['username'])
    return render_template('owner/secrets.html', secrets=secrets, messages=messages)


@app.route('/decrypt-secret/<int:secret_id>')
@login_required
def decrypt_secret(secret_id):
    from database import shared_secrets_table
    secret = shared_secrets_table.get(doc_id=secret_id)
    if not secret or secret['to_username'] != session['username']:
        return jsonify({'error': 'Access denied'}), 403
    
    user = get_user_by_username(session['username'])
    sender = get_user_by_username(secret['from_username'])
    
    try:
        decrypted = decrypt_file(secret['secret_data'], user['private_key'], sender['public_key'])
        mark_secret_as_read(secret_id)
        return jsonify({'decrypted': decrypted.decode('utf-8')})
    except Exception as e:
        return jsonify({'error': 'Decryption failed'}), 500


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
