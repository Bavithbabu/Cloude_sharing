
from phe import paillier
import sqlite3
import random
from datetime import datetime
from cryptography.fernet import Fernet
from Crypto.Hash import SHA256
import hashlib
import boto3
from botocore.exceptions import ClientError

class IntegratedCloudSystem:
    def __init__(self, s3_bucket_name, db_name="access_control.db"):
        self.s3 = boto3.client('s3')
        self.s3_bucket_name = s3_bucket_name
        self._ensure_bucket_exists()
        self.db_name = db_name
        self._initialize_db()
    
    def _ensure_bucket_exists(self):
        try:
            self.s3.head_bucket(Bucket=self.s3_bucket_name)
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                self.s3.create_bucket(Bucket=self.s3_bucket_name)
    
    def _initialize_db(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_access (
                admin TEXT,
                s3_key TEXT,
                allowed_roles TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                user TEXT,
                role TEXT,
                admin TEXT,
                status TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()
    
    def upload_file(self, owner, file_path, allowed_roles):
        try:
            with open(file_path, 'rb') as file:
                s3_key = f"{owner.lower()}/{datetime.now().isoformat()}_{file_path.split('/')[-1]}"
                self.s3.put_object(Bucket=self.s3_bucket_name, Key=s3_key, Body=file, ServerSideEncryption='AES256')

                conn = sqlite3.connect(self.db_name)
                cursor = conn.cursor()
                cursor.execute("INSERT INTO file_access (admin, s3_key, allowed_roles) VALUES (?, ?, ?)",
                            (owner.lower(), s3_key, ','.join(allowed_roles)))
                conn.commit()

                # Debugging: Print database content
                cursor.execute("SELECT * FROM file_access")
                rows = cursor.fetchall()
                print("\n📊 Database Content (file_access Table):")
                for row in rows:
                    print(row)

                conn.close()
                return s3_key
        except Exception as e:
            print(f"Upload failed: {e}")
            return None


    # def upload_file(self, owner, file_path, allowed_roles):
    #     try:
    #         with open(file_path, 'rb') as file:
    #             s3_key = f"{owner.lower()}/{datetime.now().isoformat()}_{file_path.split('/')[-1]}"
    #             self.s3.put_object(Bucket=self.s3_bucket_name, Key=s3_key, Body=file, ServerSideEncryption='AES256')
                
    #             conn = sqlite3.connect(self.db_name)
    #             cursor = conn.cursor()
    #             cursor.execute("INSERT INTO file_access (admin, s3_key, allowed_roles) VALUES (?, ?, ?)",
    #                            (owner.lower(), s3_key, ','.join(allowed_roles)))
    #             conn.commit()
    #             conn.close()
                
    #             print(f"✅ File uploaded and stored in DB under admin '{owner.lower()}'")
    #             return s3_key
    #     except Exception as e:
    #         print(f"Upload failed: {e}")
    #         return None
    
    # def access_file(self, user, role, admin):
    #     conn = sqlite3.connect(self.db_name)
    #     cursor = conn.cursor()
    #     cursor.execute("SELECT s3_key, allowed_roles FROM file_access WHERE admin = ?", (admin.lower(),))
    #     results = cursor.fetchall()
    #     conn.close()
        
    #     status = "Denied"
    #     for s3_key, allowed_roles in results:
    #         allowed_roles = allowed_roles.split(',')
    #         if role in allowed_roles:
    #             status = "Granted"
    #             self._log_access_attempt(user, role, admin, status)
    #             return self.download_file(s3_key)
        
    #     self._log_access_attempt(user, role, admin, status)
    #     return None

    def access_file(self, user, role, admin):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("SELECT s3_key, allowed_roles FROM file_access WHERE admin = ?", (admin.lower(),))
        result = cursor.fetchone()
        
        # Debugging: Check what is retrieved
        print(f"\n🧐 Debug: Retrieved Data for Admin {admin.lower()} ->", result)
        
        conn.close()
        
        status = "Denied"
        if result:
            s3_key, allowed_roles = result
            allowed_roles = allowed_roles.split(',')
            
            if role in allowed_roles:
                status = "Granted"
                self._log_access_attempt(user, role, admin, status)
                return self.download_file(s3_key)

        self._log_access_attempt(user, role, admin, status)
        return None

    
    def _log_access_attempt(self, user, role, admin, status):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO access_logs (user, role, admin, status, timestamp) VALUES (?, ?, ?, ?, ?)",
                       (user, role, admin.lower(), status, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def download_file(self, s3_key):
        try:
            file_name = s3_key.split('/')[-1]
            self.s3.download_file(self.s3_bucket_name, s3_key, file_name)
            return f"File downloaded: {file_name}"
        except Exception as e:
            print(f"Download failed: {e}")
            return None
    
    def get_audit_log(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM access_logs")
        logs = cursor.fetchall()
        conn.close()
        return logs

class DataOwner:
    def __init__(self, name, cloud_system):
        self.name = name
        self.cloud = cloud_system
    
    def upload_data(self, file_path, allowed_roles):
        return self.cloud.upload_file(self.name, file_path, allowed_roles)

class CloudUser:
    def __init__(self, name, role, cloud_system):
        self.name = name
        self.role = role
        self.cloud = cloud_system
    
    def request_access(self, admin):
        return self.cloud.access_file(self.name, self.role, admin)

class Auditor:
    def __init__(self, cloud_system):
        self.cloud = cloud_system
    
    def audit_access(self):
        logs = self.cloud.get_audit_log()
        return [f"User: {log[0]}, Role: {log[1]}, Admin: {log[2]}, Status: {log[3]}, Time: {log[4]}" for log in logs]

def test_full_system_with_s3():
    """Interactive Testing for CP-ABE + S3 Integration"""
    print("\n=== 🔍 CP-ABE + S3 Role-Based Access Test ===\n")
    
    cloud = IntegratedCloudSystem("cpabe-demo-bucket")
    admin_name = input("Enter Admin Name: ")
    admin = DataOwner(admin_name, cloud)
    
    file_path = input("Enter file path to upload: ")
    allowed_roles = input("Enter allowed roles (comma-separated): ").split(",")
    print("📂 Admin uploading a file...")
    s3_key = admin.upload_data(file_path, allowed_roles)
    
    staff_name = input("Enter User Name: ")
    staff_role = input("Enter User Role: ")
    staff = CloudUser(staff_name, staff_role, cloud)
    
    print(f"\n{staff.name} attempting to access the file uploaded by {admin_name}...")
    access_result = staff.request_access(admin_name)
    
    if access_result:
        print("✅ Access granted. File downloaded.")
    else:
        print("❌ Access denied.")
    
    auditor = Auditor(cloud)
    print("\n🔎 Audit Log:")
    print("\n".join(auditor.audit_access()))
    
    # conn = sqlite3.connect("access_control.db")
    # cursor = conn.cursor()
    # cursor.execute("SELECT * FROM file_access")
    # rows = cursor.fetchall()
    # print("file_access table contents:")
    # for row in rows:
    #     print(row)
    # conn.close()

if __name__ == "__main__":
    test_full_system_with_s3()
