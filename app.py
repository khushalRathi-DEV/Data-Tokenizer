from dotenv import load_dotenv
import os
import uuid
import sqlite3
import pandas as pd
from flask import Flask, request, render_template_string
from cryptography.fernet import Fernet
import openai

    
# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)

# Configuration (use environment variables in production!)
openai.api_key = os.getenv("OPENAI_API_KEY")
# models = openai.models.list()

# # Print the names of the models
# for model in models.data:
#     print(model.id)


VAULT_KEY = os.getenv("VAULT_KEY").encode()  # Decode the string into bytes
DB_NAME = "data_vault.db"

# Initialize encryption
cipher_suite = Fernet(VAULT_KEY)

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS token_vault
                 (token TEXT PRIMARY KEY, 
                  encrypted_value BLOB,
                  column_name TEXT)''')
    conn.commit()
    conn.close()

init_db()

# HTML Templates
HOME_PAGE = """
<!doctype html>
<html>
  <head><title>Data Tokenization Platform</title></head>
  <body>
    <h1>Secure Data Tokenization Platform</h1>
    <form action="/upload" method="post" enctype="multipart/form-data">
      <input type="file" name="file" accept=".csv">
      <input type="submit" value="Upload CSV">
    </form>
    <hr>
    <h2>Detokenize Data</h2>
    <form action="/detokenize" method="post">
      <input type="text" name="token" placeholder="Enter token">
      <input type="submit" value="Decrypt">
    </form>
  </body>
</html>
"""

# Helper Functions
def is_sensitive_column(column_name, sample_value):
    """Use LLM to classify sensitive columns"""
    try:
        response = openai.Completion.create(
            model="gpt-3.5-turbo",  # Make sure this is a valid model identifier
            prompt=f"Should this data be considered sensitive? "
                   f"Column: {column_name}, Sample Value: {sample_value}. "
                   f"Answer only 'yes' or 'no'.",
            max_tokens=5  # Keep the response small and focused
        )
        # The API now returns a `choices` field, with the text in `choices[0].text`
        return "yes" in response['choices'][0]['text'].lower()
    except Exception as e:
        print(f"LLM Error: {e}")
        return False  # Fallback to treat as sensitive


def tokenize_value(value, column_name):
    """Tokenize and store in encrypted vault"""
    token = str(uuid.uuid4())
    encrypted_value = cipher_suite.encrypt(value.encode())
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO token_vault VALUES (?, ?, ?)",
              (token, encrypted_value, column_name))
    conn.commit()
    conn.close()
    
    return token

def detokenize_value(token):
    """Retrieve and decrypt from vault"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT encrypted_value FROM token_vault WHERE token=?", (token,))
    result = c.fetchone()
    conn.close()
    
    if result:
        return cipher_suite.decrypt(result[0]).decode()
    return None

# Flask Routes
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
        
        # Process columns
        for col in df.columns:
            sample_value = str(df[col].dropna().iloc[0]) if not df[col].empty else ""
            if is_sensitive_column(col, sample_value):
                df[col] = df[col].apply(lambda x: tokenize_value(str(x), col))
        
        # Save tokenized CSV
        output_path = f"tokenized_{file.filename}"
        df.to_csv(output_path, index=False)
        
        return f"File processed successfully!<br>Download: <a href='/{output_path}'>{output_path}</a>"
    
    except Exception as e:
        return f"Error processing file: {str(e)}", 500

@app.route('/detokenize', methods=['POST'])
def detokenize():
    token = request.form.get('token', '')
    if not token:
        return "No token provided", 400
    
    original_value = detokenize_value(token)
    if original_value:
        return f"Decrypted value: {original_value}"
    return "Token not found", 404

if __name__ == '__main__':
    app.run(ssl_context='adhoc', debug=True)  # HTTPS for security