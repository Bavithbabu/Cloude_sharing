from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os
import hashlib
from tkinter import messagebox

class SecureCloudStorage:
    def __init__(self, encryptionkey):
        self.encryptionkey=encryptionkey
        if encryptionkey:
            self.key = hashlib.sha256(encryptionkey.encode('utf-8')).digest()
        else:
            self.key = get_random_bytes(32)
    
    def encrypt(self, plaintext):
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode('utf-8')
        
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, encrypted_data):
        try:
            raw_data = base64.b64decode(encrypted_data)
            nonce = raw_data[:16]
            tag = raw_data[16:32]
            ciphertext = raw_data[32:]
            
            cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        except (ValueError, KeyError) as e:
            messagebox.showerror("Decryption Error", "Invalid key or tampered data")
            raise

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted = self.encrypt(data)
        with open(file_path, 'w') as f:
            f.write(encrypted)
        print(f"✅ File encrypted: {file_path}")

    def decrypt_file(self, file_path, user_role, allowed_roles, owner):
        """
        Decrypts file only if user_role is in allowed_roles
        """
        if user_role not in allowed_roles:
            messagebox.showerror("Access Denied", 
                               f"Role '{user_role}' not authorized to access this data")
            print(f"❌ Unauthorized access attempt by role: {user_role}")
            self._notify_owner(owner, user_role)
            return False
            
        try:
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
            decrypted = self.decrypt(encrypted_data)
            decrypted_path = f"decrypted_{os.path.basename(file_path)}"
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted.encode('utf-8'))
            print(f"✅ File decrypted: {decrypted_path}")
            return True
        except Exception as e:
            print(f"❌ Decryption failed: {str(e)}")
            return False

    def _notify_owner(self, owner, user_role):
        print(f"📢 Notification sent to {owner}: Unauthorized access attempt by role {user_role}")
        # In a real system, this would send an email/notification