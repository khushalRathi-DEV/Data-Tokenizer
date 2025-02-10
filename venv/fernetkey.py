from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())  # This will generate a secure key
