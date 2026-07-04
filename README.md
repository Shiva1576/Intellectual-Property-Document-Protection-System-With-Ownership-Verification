# Intellectual Property Document Protection System With Ownership Verification
>A secure, web-based platform for managing digital IP assets and verifying ownership workflows — built with Flask, TinyDB, and advanced cryptographic techniques like ECC and AES-GCM.

---

## Abstract
The Intellectual Property (IP) Document Protection System is a secure web-based platform designed to address the vulnerabilities of traditional digital IP management, such as unauthorized access and ownership disputes. Developed using Python and the Flask web framework, the system integrates structured role-based access control with modern cryptographic safeguards. It relies on Elliptic Curve Cryptography (ECC) for secure key generation and exchange, and on AES-GCM for authenticated document encryption, guaranteeing both data integrity and confidentiality. By enforcing strict role boundaries between IP Generators, Patent Registrars, and Patent Owners, and maintaining an immutable activity log via TinyDB, the platform ensures verifiable ownership records throughout the document lifecycle.

---

## Features

-   **AES-GCM Encryption** — all uploaded documents are protected using authenticated encryption to ensure both confidentiality and data integrity during file storage.  
-   **ECC Key Management** — utilizes Elliptic Curve Cryptography for secure public/private key generation and shared symmetric key derivation.  
-   **Role-Based Access Control** — strictly enforces multi-level access permissions across distinct user dashboards to prevent unauthorized operations.
-   **Encrypted Document Workflows** — enables secure file uploading, storage, and controlled decryption specific to authorized users.  
-   **Ownership Verification** — provides a structured mechanism for users to claim approved patents and securely transfer ownership rights.  
-   **Comprehensive Audit Logging** — systematically tracks and records major system events, including logins, document uploads, approvals, and ownership changes.
-   **Secure Secret Sharing** — facilitates encrypted communication and the exchange of secret data between generators and registrars.

---

## Roles

| Role | Capabilities |
|------|-------------|
| **IP Generator** |Create IP records, upload encrypted files, share documents with registrars, and track submission status. |
| **Patent Registrar** |Review submitted IP documents, verify ownership, update registration status, and manage the central registry.|
| **Patent Owner** |Claim approved patents, download encrypted or decrypted files, transfer ownership, and view historical document activity|

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask |
| Database | TinyDB (JSON-based) |
| Encryption | ECC,AES-256 (via Python Cryptography libraries) |
| Frontend | HTML, CSS, JavaScript, Bootstrap, Jinja2 |
| Font | Figtree (Google Fonts) |

---

## Project Structure

```
IP_Document_Protection_System/
├── app.py                        # Main Flask application, routing, auth logic
├── database.py                   # TinyDB handlers and data manipulation
├── crypto_utils.py               # ECC and AES-GCM encryption/decryption functions
├── ip_system.json                # TinyDB structured database file
├── static/
│   └── uploads/                  # Protected directory for encrypted files
└── templates/
    ├── index.html                # Landing page[cite: 2]
    ├── login.html                # Authentication interface[cite: 2]
    ├── signup.html               # Registration with role selection[cite: 2]
    ├── ip_generator/             # Dashboards and forms for IP Generators[cite: 2]
    ├── registrar/                # Review panels and registry for Registrars[cite: 2]
    └── owner/                    # Ownership claims and transfer views[cite: 2]
```
## Installation & Setup

### Prerequisites

- Python 3.8+
- pip

### 1. Clone the repository

```bash
git clone https://github.com/Shiva1576/Intellectual-Property-Document-Protection-System-With-Ownership-Verification.git
cd IP_Document_Protection_System
```

### 2. Install dependencies

```bash
pip install flask tinydb cryptography werkzeug
```

### 3. Run the application

**Windows:**
```bash
run3120.bat
```

**Or directly:**
```bash
python app.py
```

The app will be available at `http://192.168.31.253:5000`

---

## Keywords
`Intellectual Property` · `Patent Protection` · `Encryption` · `Cryptography` · `Flask` · `Role-Based Access Control` · `Secure File Storage` · `Data Security` · `Authentication` · `ECC` · `AES-GCM`

## License

This project is intended for academic and demonstration purposes.

---






 
