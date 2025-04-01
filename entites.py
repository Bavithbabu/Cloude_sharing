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
        self.user_key['requested_owner'] = owner
        
        # 1. Check if owner exists
        if owner not in self.cloud.data_store:
            print("❌ Owner data not found")
            return None
            
        # 2. Check CP-ABE policy
        policy = self.cloud.keys[owner]['policy']
        if not self.cloud.check_access_policy(self.user_key, policy):
            print("❌ Access denied by CP-ABE policy")
            return None
            
        # 3. Check revocation list
        if self.user_key['user_id'] in self.cloud.keys[owner]['revoked_users']:
            print("❌ Access denied: User is revoked")
            return None
            
        # 4. Download from S3 if all checks pass
        s3_key = self.cloud.data_store[owner]
        encrypted_data = self.cloud.download_from_s3(s3_key)
        if not encrypted_data:
            print("❌ Failed to download from S3")
            return None
            
        # 5. Decrypt and return data
        key = self.cloud.keys[owner]['key']
        self.cloud.audit_log.append(f"Access granted to {self.user_key['user_id']} for {owner}'s data")
        return self.cloud.decrypt_data(key, encrypted_data)
    
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
 