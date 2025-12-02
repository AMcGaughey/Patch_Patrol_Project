from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json
import os
import base64
import re

class CitaData: 
    # initialization of storage with full security
    def __init__(self, use_encryption = True, use_keychain = True, use_validation = True):
        self.use_encryption = use_encryption
        self.use_keychain = use_keychain
        self.use_validation = use_validation
        self.storage_file = "mobile_storage.json"
        self.keychain_file = "keychain.key"
        self.data = {}

        # initialize encryption key
        if self.use_keychain:
            self.encryption_key = self._load_or_create_key()
        elif self.use_encryption:
            # hardcoded key for insecure demonstration
            self.encryption_key = Fernet.generate_key

        self._load_data()
    
    # simulates secure keychain: secure keys stored separate from data
    def _load_or_create_key(self):
        if os.path.exists(self.keychain_file):
            with open(self.keychain_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.keychain_file, 'wb') as f:
                f.write(key)
            print("Encryption key stored in secure keychain")
            return key
    
    #Input validation using both whitelisting and blacklisting
    def _validate_input(self, key, value):
        if not self.use_validation:
            return True
        
        #format check
        if not re.match(r'^[a-zA-Z0-9_-]{1,50}$', key): 
            raise ValueError("Invalid format (accepted: a-z, A-Z, 0-9, _, -)")
        if len(value) > 1000:
            raise ValueError("Value too long. (max: 1000 characters)")
        
        #common injection prevention
        dangerous_patterns = ['<script>', 'javascript:', 'onclick=', '../', '..\\']
        for pattern in dangerous_patterns:
            if pattern.lower() in value.lower():
                raise ValueError(f"Potentially malicious content detected: {pattern}")
        
        return True
    
    # data encryption: Fernet (AES-256)
    def _encrypt_data(self, data):
        if not self.use_encryption:
            return data
        
        fernet = Fernet(self.encryption_key)
        json_data = json.dumps(data)
        encrypted = fernet.encrypt(json_data.encode())
        return base64.b64encode(encrypted).decode()
    
    # data decryption
    def _decrypt_data(self, encrypted_data):
        if not self.use_encryption:
            return encrypted_data
        
        try:
            fernet = Fernet(self.encryption_key)
            decoded = base64.b64encode(encrypted_data.encode())
            decrypted = fernet.decrypt(decoded)
            return json.loads(decrypted.decode())
        except:
            return {}
    
    # saving data to storage
    def _save_data(self):
        with open(self.storage_file, 'w') as f:
            if self.use_encryption:
                encrypted = self._encrypt_data(self.data)
                f.write(encrypted)
            else:
                json.dump(self.data, f, indent = 2)

    #data loading from storage
    def _load_data(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as f:
                content = f.read()
                if self.use_encryption:
                    self.data = self._decrypt_data(content)
                else:
                    if content and content.strip():
                        self.data = json.loads(content)
                    else:
                        self.data = {}
        else:
            self.data = {}

    # storing key-value pair
    def store(self, key, value):
        try: 
            self._validate_input(key, value)
            self.data[key] = value
            self._save_data()
            print(f"Stored '{key}' successfully")
            return True
        except ValueError as e:
            print(f"Validation failed: {e}")
            return False
        
    # Value retrieval by key
    def retrieve(self, key) :
        return self.data.get(key, None)
    
    #list of stored keys
    def list_all(self):
        return list(self.data.keys())
    
    #delete key-value pair
    def delete(self, key):
        if key in self.data:
            del self.data[key]
            self._save_data()
            print(f"Deleted '{key}'")
            return True
        else:
            print(f"Key '{key}' not found")
    
    #raw storage file for demonstration
    def view_raw_storage(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as f:
                return f.read()
        return "Storage file is empty"
    
    def cleanup(self):
        """Delete the storage file"""
        if os.path.exists(self.storage_file):
            os.remove(self.storage_file)
            print(f"Storage file '{self.storage_file}' deleted.")
        

def main():
    print("=" * 60)
    print("SECURE MOBILE STORAGE DEMONSTRATION")
    print("=" * 60)
    
    # Configuration
    print("\nSecurity Configuration:")
    encryption = input("Enable Encryption? (y/n): ").lower() == 'y'
    keychain = input("Enable Secure Keychain? (y/n): ").lower() == 'y'
    validation = input("Enable Input Validation? (y/n): ").lower() == 'y'
    
    print(f"\n Encryption: {'ENABLED' if encryption else 'DISABLED'}")
    print(f" Keychain: {'ENABLED' if keychain else 'DISABLED'}")
    print(f" Input Validation: {'ENABLED' if validation else 'DISABLED'}")
    
    storage = CitaData(
        use_encryption=encryption,
        use_keychain=keychain,
        use_validation=validation
    )
    
    # Main menu
    while True:
        print("\n" + "=" * 60)
        print("MENU:")
        print("1. Store data")
        print("2. Retrieve data")
        print("3. List all keys")
        print("4. Delete data")
        print("5. View raw storage file")
        print("6. Test malicious input (if validation enabled)")
        print("0. Exit")
        print("=" * 60)
        
        choice = input("\nEnter choice (1-6)(0 to exit): ")
        
        if choice == '1':
            key = input("Enter key: ")
            value = input("Enter value: ")
            storage.store(key, value)
        
        elif choice == '2':
            key = input("Enter key: ")
            value = storage.retrieve(key)
            if value:
                print(f"Value: {value}")
            else:
                print("Key not found")
        
        elif choice == '3':
            keys = storage.list_all()
            if keys:
                print(f"Stored keys: {', '.join(keys)}")
            else:
                print("No data stored")
        
        elif choice == '4':
            key = input("Enter key to delete: ")
            storage.delete(key)
        
        elif choice == '5':
            print("\nRaw storage file content:")
            print("-" * 60)
            print(storage.view_raw_storage())
            print("-" * 60)
        
        elif choice == '6':
            print("\nTesting malicious inputs:")
            test_cases = [
                ("valid_key", "This is safe data"),
                ("invalid key!", "This has invalid characters"),
                ("xss", "<script>alert('hacked')</script>"),
                ("path_traversal", "../../../etc/passwd"),
            ]
            for key, value in test_cases:
                print(f"\nTest: key='{key}', value='{value}'")
                storage.store(key, value)
        
        elif choice == '0':
            storage.cleanup()
            print("\nExiting...")
            break
        
        else:
            print("Invalid choice")



if __name__ == "__main__":
    main()