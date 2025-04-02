class DataOwner:
    def __init__(self, name, cloud_system):
        self.name = name
        self.cloud = cloud_system
    
    def upload_data(self, data, policy, revoked_users=[]):
        """Upload data with access policy to S3"""
        # First perform local encryption
        encrypted_data = self.cloud.encrypt_data(self.name, data, policy, revoked_users)
        
        # Upload to S3 with timestamp-based key
        s3_key = f"{self.name}/{datetime.now().isoformat()}"
        if self.cloud.upload_to_s3(s3_key, encrypted_data):
            self.cloud.data_store[self.name] = s3_key  # Store S3 key reference
            self.cloud.audit_log.append(f"Data uploaded by {self.name} with policy {policy}")
            print(f"✅ Data uploaded successfully to S3 by {self.name}")
            return True
        print("❌ Failed to upload data to S3")
        return False
    
    def revoke_access(self, user_id):
        """Revoke a user's access"""
        self.cloud.revoke_user(user_id)

class CloudUser:
    def __init__(self, name, attributes, cloud_system):
        self.name = name
        self.cloud = cloud_system
        self.attributes = attributes
        self.user_key = self.cloud.generate_user_key(name, attributes)
    
    def request_access(self, owner):
        """Request access to an owner's data from S3"""
        try:
            # Retrieve the S3 key for the owner
            s3_key = self.cloud._get_s3_key(owner)
            if not s3_key:
                print("❌ Access denied: No S3 key found.")
                return None

            # Request the file from the cloud system
            decrypted_data = self.cloud.access_file(self.name, self.attributes, owner)
            if not decrypted_data:
                print("❌ Access denied.")
                return None

            # Save the file locally
            file_name = s3_key.split('/')[-1]  # Extract the file name from the S3 key
            with open(file_name, 'wb') as file:
                file.write(decrypted_data)
                print(f"✅ File '{file_name}' downloaded and saved locally.")

            return decrypted_data
        except Exception as e:
            print(f"❌ Failed to request access: {e}")
            return None
    
    def get_credentials(self):
        """Get user credentials (for debugging)"""
        return self.user_key

class Auditor:
    def __init__(self, cloud_system):
        self.cloud = cloud_system
    
    def audit_access(self):
        """Review all access logs (now includes S3 operations)"""
        return self.cloud.get_audit_log()
    
    def detect_leak(self, leaked_key):
        """Trace a leaked key back to its owner"""
        return self.cloud.trace_user(leaked_key)

class Authority:
    def __init__(self, cloud_system):
        self.cloud = cloud_system
    
    def revoke_user(self, user_id):
        """Revoke a user's access across the system"""
        self.cloud.revoke_user(user_id)
