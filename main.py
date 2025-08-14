from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import hashlib
import sqlite3

# Function to encrypt data using AES with a key
def encrypt(data: str, key: str) -> str:
    # Hash the key to make sure it's 32 bytes
    key = hashlib.sha256(key.encode()).digest()  # Use SHA-256 to generate a 32-byte key
    
    # Generate a random IV
    iv = b'0123456789abcdef'  # You can generate this dynamically (just for simplicity here)
    
    # Pad the data to be a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()

    # Set up the AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return both the IV and encrypted data as base64 for easy storage
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

# Function to decrypt data using AES with a key
def decrypt(encrypted_data: str, key: str) -> str:
    try:
        # Hash the key to make sure it's 32 bytes
        key = hashlib.sha256(key.encode()).digest()  # Use SHA-256 to generate a 32-byte key

        # Decode the base64 encoded encrypted data
        encrypted_data = base64.b64decode(encrypted_data)

        # Extract the IV from the encrypted data (first 16 bytes)
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]

        # Set up the AES cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the data correctly using PKCS7
        unpadder = padding.PKCS7(128).unpadder()  # Ensure padding is correct for 128-bit blocks
        original_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return original_data.decode('utf-8')
    except ValueError as e:
        # print("Error during decryption:", e)
        return None  # Return None or handle the error as you see fit


# Example usage
# password = "this is my message"
# key = "ihysmcujd"

# Encrypt the password
# encrypted_password = encrypt(password, key)
# print("Encrypted Password:", encrypted_password)

# # Decrypt the password
# decrypted_password = decrypt(encrypted_password, key)
# print("Decrypted Password:", decrypted_password)

def retrieve_entries(decryption_key: str):
    # Connect to the SQLite database
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()

    # Query to retrieve id, what, username, and password from the accounts table
    cursor.execute("SELECT id, what, username, password FROM accounts")
    entries = cursor.fetchall()

    # Print all entries neatly
    print("ID | What | Username | Password")
    print("-" * 50)  # For better readability
    for entry in entries:
        # Decrypt the password using the provided key
        decrypted_password = decrypt(entry[3], decryption_key)
        print(f"{entry[0]} | {entry[1]} | {entry[2]} | {decrypted_password}")

    # Close the connection
    conn.close()
    
def deleteEntry(entryId):
    conn = sqlite3.connect('db.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM accounts WHERE id = {entryId}")
    conn.commit()


def initiate():
  option = int(input("what do u want to do? \n1: add entry \n2: retrieve entry\n3: delete an entry\n"))
  conn = sqlite3.connect('db.db')
  cursor = conn.cursor()
  if option == 1:
    key = input("key? ")
    website = input("website? ")
    username = input("username? ")
    password1 = ""
    password2 ="."
    while password1 != password2:
      password1 = input("password? ")
      password2 = input("password again? ")
    cursor.execute('''
    INSERT INTO accounts (username, password, what)
    VALUES (?, ?, ?)
    ''', (username, encrypt(password1, key), website))
    print(f"added with the key: ${key}")
    conn.commit()
    initiate()
  elif option == 2:
    key = input("key? ")
    retrieve_entries(key)
    initiate( )
  elif option == 3:
    id = input("what is the id? ")
    deleteEntry(id)
    print("successfully delete id " + id)
    initiate()
  else:
    print("did not write 1 or 2")
    initiate()

initiate()