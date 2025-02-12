from dotenv import load_dotenv
import os
import uuid
import sqlite3
import pandas as pd
import shutil
from flask import Flask, request, render_template_string, send_from_directory
from cryptography.fernet import Fernet
import google.generativeai as genai
import json
from datetime import datetime
import pandas as pd
from io import StringIO

# Load environment variables
load_dotenv()
app = Flask(__name__)

# Configuration
DB_NAME = "data_vault.db"
UPLOAD_FOLDER = "tokenized_files"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

#check this
if os.path.exists(UPLOAD_FOLDER):
    shutil.rmtree(UPLOAD_FOLDER)
os.makedirs(UPLOAD_FOLDER)

# Configure Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

# Initialize encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# HTML template for the home page
HOME_PAGE = """
<!doctype html>
<html>
  <head>
    <title>Data Tokenization Platform</title>
    <style>
      body { 
        font-family: Arial, sans-serif; 
        max-width: 800px; 
        margin: 0 auto; 
        padding: 20px; 
      }
      .container { 
        background: #f5f5f5; 
        padding: 20px; 
        border-radius: 5px; 
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      .error { color: #dc3545; }
      .success { color: #28a745; }
      input[type="submit"] { 
        background: #4CAF50; 
        color: white; 
        padding: 10px 20px; 
        border: none; 
        border-radius: 4px; 
        cursor: pointer; 
      }
      input[type="submit"]:hover { 
        background: #45a049; 
      }
      input[type="file"], input[type="text"] { 
        padding: 10px; 
        margin: 10px 0; 
        width: 100%; 
        box-sizing: border-box; 
        border: 1px solid #ddd;
        border-radius: 4px;
      }
      .section {
        margin-bottom: 30px;
        padding: 20px;
        background: white;
        border-radius: 5px;
      }
      h1, h2 { 
        color: #333;
        margin-top: 0;
      }
      hr {
        border: none;
        border-top: 1px solid #ddd;
        margin: 20px 0;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Secure Data Tokenization Platform</h1>
      
      <div class="section">
        <h2>Upload and Tokenize Data</h2>
        <form action="/upload" method="post" enctype="multipart/form-data">
          <input type="file" name="file" accept=".csv" required>
          <input type="submit" value="Upload CSV">
        </form>
      </div>
      
      <div class="section">
        <h2>View Tokenized Data</h2>
        <a href="/view_data" style="text-decoration: none;">
          <input type="submit" value="View Data" style="width: 100%;">
        </a>
      </div>
       <div class="section">
        <h2>Detokenize Data</h2>
        <form action="/detokenize" method="post" enctype="multipart/form-data">
          <input type="file" name="file" accept=".csv" required>
          <input type="submit" value="Detokenize CSV">
        </form>
      </div>
    </div>
  </body>
</html>
"""

def init_db():
    """Initialize SQLite database"""
    # Delete existing database if it exists
    if os.path.exists(DB_NAME):
        os.remove(DB_NAME)
        
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Create records table
    c.execute('''CREATE TABLE IF NOT EXISTS records
                 (record_id TEXT PRIMARY KEY,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create token_vault table with all required columns
    c.execute('''CREATE TABLE IF NOT EXISTS token_vault
                 (token TEXT PRIMARY KEY,
                  record_id TEXT,
                  encrypted_value BLOB,
                  column_name TEXT,
                  sensitivity_reason TEXT,
                  data_category TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (record_id) REFERENCES records(record_id))''')
    
    conn.commit()
    conn.close()

def analyze_column_sensitivity(column_name, sample_values):
    """
    Use Gemini to determine if a column contains sensitive data
    """
    try:
        # Prepare sample values for analysis
        samples = sample_values[:3]  # Take up to 3 samples for analysis
        
        # Construct the prompt for Gemini
        prompt = f"""Analyze if this data column contains sensitive information that requires encryption.
Column Name: {column_name}
Sample Values: {samples}

Your response must be a valid JSON object with exactly these fields:
{{"is_sensitive": true/false, "reason": "brief explanation", "data_category": "category name"}}

Categories can be: PII, Financial, Healthcare, Contact, Location, Professional, or AadharID or any other government ID or General. """

        # Get response from Gemini
        response = model.generate_content(prompt, safety_settings=[
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_NONE"
            }
        ])
        
        try:
            # Try to get response text
            response_text = response.text
            result = json.loads(response_text)
        except:
            # If that fails, fall back to rule-based analysis
            return analyze_column_sensitivity_fallback(column_name, sample_values)
            
        return result["is_sensitive"], result["reason"], result["data_category"]
        
    except Exception as e:
        print(f"Error in sensitivity analysis: {e}")
        return analyze_column_sensitivity_fallback(column_name, sample_values)

def analyze_column_sensitivity_fallback(column_name, sample_values):
    """
    Fallback method using rule-based analysis when API fails
    """
    sensitive_patterns = {
        'PII': ['email', 'phone', 'address', 'ssn', 'social', 'birth', 'passport','AadharID'],
        'Financial': ['account', 'card', 'credit', 'debit', 'payment', 'salary', 'income'],
        'Healthcare': ['health', 'medical', 'diagnosis', 'patient', 'treatment'],
        'Location': ['address', 'location', 'gps', 'coordinates', 'zip', 'postal'],
        'Professional': ['employee', 'salary', 'position', 'department', 'manager'],
        'Contact': ['email', 'phone', 'mobile', 'fax', 'contact']
    }
    
    column_lower = column_name.lower()
    
    # Check column name against patterns
    for category, patterns in sensitive_patterns.items():
        if any(pattern in column_lower for pattern in patterns):
            return True, f"Column name contains sensitive {category} information", category
    
    # Check sample values for patterns
    sample_str = ' '.join(str(v) for v in sample_values).lower()
    for category, patterns in sensitive_patterns.items():
        if any(pattern in sample_str for pattern in patterns):
            return True, f"Sample values contain sensitive {category} information", category
    
    return False, "No sensitive patterns detected", "General"

def tokenize_row(row_data, sensitivity_info):
    """Tokenize a row of data using sensitivity information"""
    conn = None
    try:
        record_id = str(uuid.uuid4())
        tokens = {}
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Create record entry
        c.execute("INSERT INTO records (record_id) VALUES (?)", (record_id,))
        
        # Process each column
        for column_name, value in row_data.items():
            if column_name in sensitivity_info and sensitivity_info[column_name]["is_sensitive"]:
                token = str(uuid.uuid4())
                encrypted_value = cipher_suite.encrypt(str(value).encode())
                
                c.execute("""
                    INSERT INTO token_vault 
                    (token, record_id, encrypted_value, column_name, sensitivity_reason, data_category)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (token, record_id, encrypted_value, column_name, 
                     sensitivity_info[column_name]["reason"],
                     sensitivity_info[column_name]["category"]))
                
                tokens[column_name] = token
            else:
                tokens[column_name] = value
        
        conn.commit()
        return tokens
    
    except Exception as e:
        print(f"Error tokenizing row: {e}")
        if conn:
            conn.rollback()
        return None
    
    finally:
        if conn:
            conn.close()

def is_uuid(value):
    """Check if a value looks like a UUID token"""
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False

def detokenize_dataframe(df):
    """Process a dataframe and detokenize values where possible"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Get all tokens from the database
    c.execute("SELECT token, encrypted_value FROM token_vault")
    token_map = {row[0]: cipher_suite.decrypt(row[1]).decode() for row in c.fetchall()}
    
    # Process each column
    for column in df.columns:
        # Check each value in the column
        for idx, value in enumerate(df[column]):
            if is_uuid(value) and str(value) in token_map:
                df.at[idx, column] = token_map[str(value)]
    
    conn.close()
    return df

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

@app.route('/')
def home():
    return render_template_string(HOME_PAGE)

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
        
        # Analyze each column for sensitivity
        sensitivity_info = {}
        for column in df.columns:
            sample_values = df[column].dropna().head(3).tolist()
            is_sensitive, reason, category = analyze_column_sensitivity(column, sample_values)
            sensitivity_info[column] = {
                "is_sensitive": is_sensitive,
                "reason": reason,
                "category": category
            }
        
        # Process each row
        tokenized_rows = []
        failed_rows = 0
        
        for index, row in df.iterrows():
            tokenized_row = tokenize_row(row, sensitivity_info)
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
        
        # Prepare sensitivity report
        sensitivity_report = """
        <h3>Column Sensitivity Analysis:</h3>
        <table class="sensitivity-table">
            <tr>
                <th>Column</th>
                <th>Sensitive?</th>
                <th>Reason</th>
                <th>Category</th>
            </tr>
        """
        
        for column, info in sensitivity_info.items():
            sensitivity_report += f"""
            <tr>
                <td>{column}</td>
                <td>{"Yes" if info["is_sensitive"] else "No"}</td>
                <td>{info["reason"]}</td>
                <td>{info["category"]}</td>
            </tr>
            """
        
        sensitivity_report += "</table>"
        
        return f"""
        <div class="success">
            <h3>File processed successfully!</h3>
            <p>{len(tokenized_rows)} rows were successfully processed and stored.</p>
            {sensitivity_report}
            <p><a href='/download/{output_filename}' class="download-link">Download Tokenized File</a></p>
            <p><a href='/view_data' class="download-link">View Stored Data</a></p>
        </div>
        <style>
            .sensitivity-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                margin-bottom: 20px;
            }}
            .sensitivity-table th, .sensitivity-table td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            .sensitivity-table th {{
                background-color: #4CAF50;
                color: white;
            }}
            .sensitivity-table tr:nth-child(even) {{
                background-color: #f2f2f2;
            }}
            .download-link {{
                display: inline-block;
                margin: 10px 0;
                padding: 10px 20px;
                background: #4CAF50;
                color: white;
                text-decoration: none;
                border-radius: 4px;
            }}
            .download-link:hover {{
                background: #45a049;
            }}
        </style>
        """
    
    except Exception as e:
        return f"""
        <div class="error">
            <h3>Error processing file</h3>
            <p>{str(e)}</p>
        </div>
        """, 500
    
@app.route('/view_data')
def view_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Get all records with their related data
        c.execute("""
            SELECT r.record_id, r.created_at, v.column_name, v.token, v.encrypted_value,
                   v.sensitivity_reason, v.data_category
            FROM records r
            LEFT JOIN token_vault v ON r.record_id = v.record_id
            ORDER BY r.created_at DESC
        """)
        
        data = c.fetchall()
        
        # Organize data by record
        records_dict = {}
        for row in data:
            record_id, created_at, column_name, token, encrypted_value, reason, category = row
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
                        'value': decrypted_value,
                        'reason': reason,
                        'category': category
                    })
                except Exception as e:
                    records_dict[record_id]['data'].append({
                        'column': column_name,
                        'token': token,
                        'value': 'Error decrypting',
                        'reason': reason,
                        'category': category
                    })
        
        conn.close()
        
        # Create HTML response
        html = """
        <!doctype html>
        <html>
        <head>
            <title>Stored Data View</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    padding: 20px; 
                    max-width: 1200px; 
                    margin: 0 auto; 
                }
                .container {
                    background: #f5f5f5;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                table { 
                    border-collapse: collapse; 
                    width: 100%; 
                    margin-top: 20px;
                    background: white;
                }
                th, td { 
                    border: 1px solid #ddd; 
                    padding: 12px 8px; 
                    text-align: left; 
                }
                th { 
                    background-color: #4CAF50; 
                    color: white; 
                }
                tr:nth-child(even) { 
                    background-color: #f9f9f9; 
                }
                .record-header { 
                    background-color: #e9ecef;
                    font-weight: bold; 
                }
                .back-button {
                    display: inline-block;
                    margin: 20px 0;
                    padding: 10px 20px;
                    background: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 4px;
                }
                .back-button:hover {
                    background: #45a049;
                }
                .category-pill {
                    padding: 4px 8px;
                    border-radius: 12px;
                    font-size: 0.85em;
                    background: #e9ecef;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <a href="/" class="back-button">← Back to Home</a>
                <h1>Stored Encrypted Data</h1>
                <table>
                    <tr>
                        <th>Record ID</th>
                        <th>Created At</th>
                        <th>Column</th>
                        <th>Category</th>
                        <th>Token</th>
                        <th>Decrypted Value</th>
                        <th>Sensitivity Reason</th>
                    </tr>
        """
        
        for record_id, record_data in records_dict.items():
            for data_item in record_data['data']:
                html += f"""
                <tr>
                    <td>{record_id}</td>
                    <td>{record_data['created_at']}</td>
                    <td>{data_item['column']}</td>
                    <td><span class="category-pill">{data_item['category']}</span></td>
                    <td>{data_item['token']}</td>
                    <td>{data_item['value']}</td>
                    <td>{data_item['reason']}</td>
                </tr>
                """
        
        html += """
                </table>
            </div>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        return f"""
        <div style="color: red; padding: 20px;">
            <h2>Error Viewing Data</h2>
            <p>Error: {str(e)}</p>
            <p><a href="/" class="back-button">← Back to Home</a></p>
        </div>
        """, 500

@app.route('/detokenize', methods=['POST'])
def detokenize_file():
    if 'file' not in request.files:
        return "No file uploaded", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400
    
    try:
        # Read CSV
        df = pd.read_csv(file)
        
        # Detokenize the dataframe
        detokenized_df = detokenize_dataframe(df)
        
        # Generate unique filename for detokenized file
        output_filename = f"detokenized_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        output_path = os.path.join(UPLOAD_FOLDER, output_filename)
        
        # Save detokenized file
        detokenized_df.to_csv(output_path, index=False)
        
        return f"""
        <div class="success">
            <h3>File Detokenized Successfully!</h3>
            <p>Your file has been processed and detokenized.</p>
            <p><a href='/download/{output_filename}' class="download-link">Download Detokenized File</a></p>
            <p><a href='/' class="download-link">Back to Home</a></p>
        </div>
        <style>
            .success {{
                padding: 20px;
                background-color: #f5f5f5;
                border-radius: 5px;
                margin: 20px;
            }}
            .download-link {{
                display: inline-block;
                margin: 10px 0;
                padding: 10px 20px;
                background: #4CAF50;
                color: white;
                text-decoration: none;
                border-radius: 4px;
            }}
            .download-link:hover {{
                background: #45a049;
            }}
        </style>
        """
    
    except Exception as e:
        return f"""
        <div class="error">
            <h3>Error Processing File</h3>
            <p>{str(e)}</p>
            <p><a href='/' class="download-link">Back to Home</a></p>
        </div>
        """, 500

@app.route('/download/<filename>')
def download_file(filename):
    """Route to handle file downloads"""
    try:
        return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)
    except Exception as e:
        return f"Error downloading file: {str(e)}", 404

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Ensure upload folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)