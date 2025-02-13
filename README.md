# Data-Tokenizer

**Data-Tokenizer** is a Python-based tool that enables the uploading of CSV files containing sensitive data. Using AI, it automatically segregates sensitive and non-sensitive information, tokenizes the sensitive data, and stores it in an encrypted database. This helps ensure that sensitive information is securely handled and processed while maintaining data privacy.

## Features

- Upload CSV files containing sensitive and non-sensitive data.
- AI-based segregation of sensitive and non-sensitive information.
- Tokenization of sensitive data to enhance security.
- Stores the tokenized sensitive data into an encrypted SQLite database.
- Allows you to easily manage and retrieve the tokenized data.

## Installation

To get started with Data-Tokenizer, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/khushalRathi-DEV/Data-Tokenizer.git

2. Navigate into the project directory:
    ```bash
      cd Data-Tokenizer
3.Install the required dependencies:
    ```bash
    
      pip install -r requirements.txt
4.Usage
To run the main tokenizer script, execute the following:
    ```bash
    
    python app.py
## NOTE
Ensure you upload your CSV file with sensitive data when prompted. The tool will automatically detect sensitive information, tokenize it, and store the tokenized data in an encrypted database.

## Project Structure

Data-Tokenizer/
│
├── app.py              # Main application for uploading, segregating, and tokenizing data
├── app2.py             # Additional script for extended functionality
├── app3.py             # Another script for different tokenization purposes
├── app4.py             # Additional utility script
├── tokenized_input.csv # Sample tokenized data in CSV format
├── data_vault.db       # SQLite database to store encrypted tokenized data
└── venv/               # Virtual environment for dependencies
## Contributing
If you want to contribute to this project, feel free to fork the repository and submit pull requests. Issues and feature requests are welcome.
