from dotenv import load_dotenv
import os
import uuid
import sqlite3
import pandas as pd
from flask import Flask, request, render_template_string, send_from_directory
from cryptography.fernet import Fernet
import re
from datetime import datetime

# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)

# Configuration
DB_NAME = "data_vault.db"
UPLOAD_FOLDER = "tokenized_files"  # Folder to store tokenized files

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Generate a new key if not exists
def get_or_create_key():
    key_file = ".vault_key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        return key

VAULT_KEY = os.getenv("VAULT_KEY", "").encode() or get_or_create_key()
cipher_suite = Fernet(VAULT_KEY)

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    'email': r'^[\w\.-]+@[\w\.-]+\.\w+$',
    'phone': r'^\+?1?\d{9,15}$',
    'ssn': r'^\d{3}-?\d{2}-?\d{4}$',
    'credit_card': r'^\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}$',
    'date_of_birth': r'^\d{4}-\d{2}-\d{2}$'
}

# Common sensitive column names
SENSITIVE_COLUMNS = {
    'ssn', 'social_security', 'credit_card', 'cc_number', 'password',
    'email', 'phone', 'address', 'dob', 'date_of_birth', 'salary',
    'bank_account', 'account_number'
}

def init_db():
    """Initialize SQLite database with improved schema for related data"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Create a records table to group related data
    c.execute('''CREATE TABLE IF NOT EXISTS records
                 (record_id TEXT PRIMARY KEY,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Modified token_vault table with record relationship
    c.execute('''CREATE TABLE IF NOT EXISTS token_vault
                 (token TEXT PRIMARY KEY,
                  record_id TEXT,
                  encrypted_value BLOB,
                  column_name TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (record_id) REFERENCES records(record_id))''')
    
    conn.commit()
    conn.close()

init_db()

def tokenize_row(row_data):
    """Tokenize an entire row of data while maintaining relationships"""
    try:
        record_id = str(uuid.uuid4())
        tokens = {}
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Create record entry
        c.execute("INSERT INTO records (record_id) VALUES (?)", (record_id,))
        
        # Process each column in the row
        for column_name, value in row_data.items():
            if is_sensitive_column(column_name, str(value)):
                token = str(uuid.uuid4())
                encrypted_value = cipher_suite.encrypt(str(value).encode())
                
                c.execute("""
                    INSERT INTO token_vault (token, record_id, encrypted_value, column_name)
                    VALUES (?, ?, ?, ?)
                """, (token, record_id, encrypted_value, column_name))
                
                tokens[column_name] = token
            else:
                tokens[column_name] = value
        
        conn.commit()
        conn.close()
        return tokens
    
    except Exception as e:
        print(f"Error tokenizing row: {e}")
        return None

# Add function to view database contents
def view_database_contents():
    """Function to view database contents in a readable format"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    print("\n=== Records Table ===")
    c.execute("SELECT * FROM records")
    records = c.fetchall()
    for record in records:
        print(f"\nRecord ID: {record[0]}")
        print(f"Created at: {record[1]}")
        
        # Get all tokens for this record
        c.execute("""
            SELECT column_name, token, encrypted_value 
            FROM token_vault 
            WHERE record_id = ?
        """, (record[0],))
        tokens = c.fetchall()
        print("\nSensitive Data:")
        for token_data in tokens:
            column_name, token, encrypted_value = token_data
            try:
                decrypted_value = cipher_suite.decrypt(encrypted_value).decode()
                print(f"  {column_name}: {token} (Decrypted: {decrypted_value})")
            except Exception as e:
                print(f"  {column_name}: {token} (Error decrypting: {str(e)})")
    
    conn.close()

def is_sensitive_column(column_name, sample_value):
    """Rule-based classifier for sensitive data"""
    # Check if column name indicates sensitive data
    column_lower = column_name.lower().replace('_', '')
    if any(sensitive in column_lower for sensitive in SENSITIVE_COLUMNS):
        return True
    
    # Check if sample value matches sensitive patterns
    sample_str = str(sample_value)
    for pattern in SENSITIVE_PATTERNS.values():
        if re.match(pattern, sample_str):
            return True
            
    return False

def tokenize_value(value, column_name):
    """Tokenize and store in encrypted vault with error handling"""
    try:
        token = str(uuid.uuid4())
        encrypted_value = cipher_suite.encrypt(str(value).encode())
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO token_vault (token, encrypted_value, column_name) VALUES (?, ?, ?)",
                  (token, encrypted_value, column_name))
        conn.commit()
        conn.close()
        
        return token
    except Exception as e:
        print(f"Error tokenizing value: {e}")
        return "ERROR_TOKENIZING"

def detokenize_value(token):
    """Retrieve and decrypt from vault with error handling"""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT encrypted_value FROM token_vault WHERE token=?", (token,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return cipher_suite.decrypt(result[0]).decode()
        return None
    except Exception as e:
        print(f"Error detokenizing value: {e}")
        return None

def generate_unique_filename(original_filename):
    """Generate a unique filename with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name, ext = os.path.splitext(original_filename)
    return f"tokenized_{name}_{timestamp}{ext}"

# Improved HTML template with better styling and feedback
HOME_PAGE = """
<!doctype html>
<html>
  <head>
    <title>Data Tokenization Platform</title>
    <style>
      body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
      .container { background: #f5f5f5; padding: 20px; border-radius: 5px; }
      .error { color: red; }
      .success { color: green; }
      input[type="submit"] { background: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
      input[type="submit"]:hover { background: #45a049; }
      input[type="file"], input[type="text"] { padding: 10px; margin: 10px 0; width: 100%; box-sizing: border-box; }
      .download-link { display: inline-block; margin-top: 10px; padding: 10px 20px; background: #008CBA; color: white; text-decoration: none; border-radius: 4px; }
      .download-link:hover { background: #007B9E; }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Secure Data Tokenization Platform</h1>
      <div>
        <h2>Upload and Tokenize Data</h2>
        <form action="/upload" method="post" enctype="multipart/form-data">
          <input type="file" name="file" accept=".csv" required>
          <input type="submit" value="Upload CSV">
        </form>
      </div>
      <hr>
      <div>
        <h2>Detokenize Data</h2>
        <form action="/detokenize" method="post">
          <input type="text" name="token" placeholder="Enter token" required>
          <input type="submit" value="Decrypt">
        </form>
      </div>
    </div>
  </body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HOME_PAGE)

def recreate_database():
    """Recreate the database with the correct schema"""
    # If database exists, delete it to start fresh
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Create records table
    c.execute('''CREATE TABLE IF NOT EXISTS records
                 (record_id TEXT PRIMARY KEY,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create token_vault table with the correct schema
    c.execute('''CREATE TABLE IF NOT EXISTS token_vault
                 (token TEXT PRIMARY KEY,
                  record_id TEXT,
                  encrypted_value BLOB,
                  column_name TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (record_id) REFERENCES records(record_id))''')
    
    conn.commit()
    conn.close()

# Function to check if database needs migration
def check_db_schema():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Check if the record_id column exists in token_vault
        c.execute("PRAGMA table_info(token_vault)")
        columns = [column[1] for column in c.fetchall()]
        
        conn.close()
        
        if 'record_id' not in columns:
            print("Database schema outdated, recreating database...")
            recreate_database()
            return True
            
        return False
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        recreate_database()
        return True

# Add this at the start of your main code, before any database operations
recreate_database()  # For now, let's recreate it every time to ensure correct schema

@app.route('/debug/db_status')
def db_status():
    """Debug route to check database status"""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Get table counts
        c.execute("SELECT COUNT(*) FROM records")
        records_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM token_vault")
        tokens_count = c.fetchone()[0]
        
        # Get sample data
        c.execute("SELECT * FROM records LIMIT 5")
        sample_records = c.fetchall()
        
        c.execute("SELECT * FROM token_vault LIMIT 5")
        sample_tokens = c.fetchall()
        
        conn.close()
        
        return f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; padding: 20px; }}
                .debug-info {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .count-info {{ color: #333; margin: 10px 0; }}
                .sample-data {{ margin-top: 20px; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
            </style>
        </head>
        <body>
            <div class="debug-info">
                <h2>Database Status</h2>
                <div class="count-info">
                    <p>Database file: {os.path.abspath(DB_NAME)}</p>
                    <p>Records count: {records_count}</p>
                    <p>Token vault entries: {tokens_count}</p>
                </div>
                
                <div class="sample-data">
                    <h3>Sample Records</h3>
                    <table>
                        <tr><th>Record ID</th><th>Created At</th></tr>
                        {"".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td></tr>" for r in sample_records)}
                    </table>
                    
                    <h3>Sample Tokens</h3>
                    <table>
                        <tr><th>Token</th><th>Record ID</th><th>Column Name</th></tr>
                        {"".join(f"<tr><td>{t[0]}</td><td>{t[1]}</td><td>{t[3]}</td></tr>" for t in sample_tokens)}
                    </table>
                </div>
            </div>
        </body>
        </html>
        """
        
    except Exception as e:
        return f"""
        <div style="color: red; padding: 20px;">
            <h2>Database Error</h2>
            <p>Error accessing database: {str(e)}</p>
            <p>Database path: {os.path.abspath(DB_NAME)}</p>
        </div>
        """

@app.route('/test/add_record')
def test_add_record():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        record_id = str(uuid.uuid4())
        c.execute("INSERT INTO records (record_id) VALUES (?)", (record_id,))
        
        test_value = "test@email.com"
        token = str(uuid.uuid4())
        encrypted_value = cipher_suite.encrypt(test_value.encode())
        
        c.execute("""
            INSERT INTO token_vault (token, record_id, encrypted_value, column_name)
            VALUES (?, ?, ?, ?)
        """, (token, record_id, encrypted_value, "email"))
        
        conn.commit()
        conn.close()
        
        return "Test record added successfully!"
        
    except Exception as e:
        return f"Error adding test record: {str(e)}"

@app.route('/test/show_data')
def show_test_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Get all records with their token data
        c.execute("""
            SELECT 
                r.record_id,
                r.created_at,
                t.token,
                t.column_name,
                t.encrypted_value
            FROM records r
            LEFT JOIN token_vault t ON r.record_id = t.record_id
        """)
        
        data = c.fetchall()
        conn.close()
        
        html = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; padding: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #4CAF50; color: white; }
                .record { background-color: #f9f9f9; }
            </style>
        </head>
        <body>
            <h2>Database Contents</h2>
            <table>
                <tr>
                    <th>Record ID</th>
                    <th>Created At</th>
                    <th>Token</th>
                    <th>Column Name</th>
                    <th>Decrypted Value</th>
                </tr>
        """
        
        for row in data:
            record_id, created_at, token, column_name, encrypted_value = row
            try:
                decrypted = cipher_suite.decrypt(encrypted_value).decode() if encrypted_value else "N/A"
            except:
                decrypted = "Error decrypting"
                
            html += f"""
                <tr class="record">
                    <td>{record_id}</td>
                    <td>{created_at}</td>
                    <td>{token}</td>
                    <td>{column_name}</td>
                    <td>{decrypted}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"Error querying database: {str(e)}"

# Modified tokenize_row function with better error handling
def tokenize_row(row_data):
    """Tokenize an entire row of data while maintaining relationships"""
    conn = None
    try:
        record_id = str(uuid.uuid4())
        tokens = {}
        
        print(f"Processing row with record_id: {record_id}")  # Debug log
        print(f"Row data: {row_data}")  # Debug log
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Create record entry
        c.execute("INSERT INTO records (record_id) VALUES (?)", (record_id,))
        print(f"Inserted record_id: {record_id}")  # Debug log
        
        # Process each column in the row
        for column_name, value in row_data.items():
            if is_sensitive_column(column_name, str(value)):
                token = str(uuid.uuid4())
                encrypted_value = cipher_suite.encrypt(str(value).encode())
                
                c.execute("""
                    INSERT INTO token_vault (token, record_id, encrypted_value, column_name)
                    VALUES (?, ?, ?, ?)
                """, (token, record_id, encrypted_value, column_name))
                
                tokens[column_name] = token
                print(f"Tokenized {column_name}: {token}")  # Debug log
            else:
                tokens[column_name] = value
        
        conn.commit()
        print("Successfully committed transaction")  # Debug log
        return tokens
    
    except Exception as e:
        print(f"Error in tokenize_row: {e}")  # Debug log
        if conn:
            conn.rollback()
        return None
    
    finally:
        if conn:
            conn.close()

# Modified upload_file route with better error handling
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file uploaded", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400
    
    try:
        # Read CSV
        df = pd.read_csv(file)
        
        # Process each row
        tokenized_rows = []
        failed_rows = 0
        
        for index, row in df.iterrows():
            tokenized_row = tokenize_row(row)
            if tokenized_row:
                tokenized_rows.append(tokenized_row)
            else:
                failed_rows += 1
        
        if not tokenized_rows:
            return """
            <div class="error">
                <h3>Processing Failed</h3>
                <p>No rows were successfully processed.</p>
            </div>
            """, 500
        
        # Create new dataframe with tokenized data
        tokenized_df = pd.DataFrame(tokenized_rows)
        
        # Generate unique filename and save
        output_filename = generate_unique_filename(file.filename)
        output_path = os.path.join(UPLOAD_FOLDER, output_filename)
        tokenized_df.to_csv(output_path, index=False)
        
        status_message = ""
        if failed_rows > 0:
            status_message = f"<p class='warning'>Note: {failed_rows} rows failed to process.</p>"
        
        return f"""
        <div class="success">
            <h3>File processed successfully!</h3>
            <p>{len(tokenized_rows)} rows were successfully processed and stored.</p>
            {status_message}
            <p><a href='/download/{output_filename}' class="download-link">Download Tokenized File</a></p>
            <p><a href='/view_data' class="download-link">View Stored Data</a></p>
        </div>
        """
    
    except Exception as e:
        return f"""
        <div class="error">
            <h3>Error processing file</h3>
            <p>{str(e)}</p>
        </div>
        """, 500
# Add route to view data
@app.route('/view_data')
def view_data():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Get all records with their related data
    c.execute("""
        SELECT r.record_id, r.created_at, v.column_name, v.token, v.encrypted_value
        FROM records r
        LEFT JOIN token_vault v ON r.record_id = v.record_id
        ORDER BY r.created_at DESC
    """)
    
    data = c.fetchall()
    
    # Organize data by record
    records_dict = {}
    for row in data:
        record_id, created_at, column_name, token, encrypted_value = row
        if record_id not in records_dict:
            records_dict[record_id] = {
                'created_at': created_at,
                'data': []
            }
        if encrypted_value:  # Only add if there's encrypted data
            try:
                decrypted_value = cipher_suite.decrypt(encrypted_value).decode()
                records_dict[record_id]['data'].append({
                    'column': column_name,
                    'token': token,
                    'value': decrypted_value
                })
            except Exception as e:
                records_dict[record_id]['data'].append({
                    'column': column_name,
                    'token': token,
                    'value': 'Error decrypting'
                })
    
    conn.close()
    
    # Create HTML table
    html = """
    <!doctype html>
    <html>
    <head>
        <title>Stored Data View</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #4CAF50; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .record-header { background-color: #ddd; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>Stored Encrypted Data</h1>
        <table>
            <tr>
                <th>Record ID</th>
                <th>Created At</th>
                <th>Column</th>
                <th>Token</th>
                <th>Decrypted Value</th>
            </tr>
    """
    
    for record_id, record_data in records_dict.items():
        for data_item in record_data['data']:
            html += f"""
            <tr>
                <td>{record_id}</td>
                <td>{record_data['created_at']}</td>
                <td>{data_item['column']}</td>
                <td>{data_item['token']}</td>
                <td>{data_item['value']}</td>
            </tr>
            """
    
    html += """
        </table>
    </body>
    </html>
    """
    
    return html

@app.route('/download/<filename>')
def download_file(filename):
    """Route to handle file downloads"""
    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except Exception as e:
        return f"Error downloading file: {str(e)}", 404

@app.route('/detokenize', methods=['POST'])
def detokenize():
    token = request.form.get('token', '')
    if not token:
        return "No token provided", 400
    
    original_value = detokenize_value(token)
    if original_value:
        return f"""
        <div class="success">
            <h3>Decryption Successful</h3>
            <p>Decrypted value: {original_value}</p>
        </div>
        """
    return """
    <div class="error">
        <h3>Decryption Failed</h3>
        <p>Token not found or invalid</p>
    </div>
    """, 404

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)