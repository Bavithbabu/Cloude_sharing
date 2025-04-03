import csv
import os
import boto3
from datetime import datetime
from botocore.exceptions import ClientError


class IntegratedCloudSystem:
    def __init__(self, s3_bucket_name, csv_file='access_records.csv'):
        self.s3 = boto3.client('s3', region_name='ap-south-1')
        self.s3_bucket_name = s3_bucket_name
        self.csv_file = csv_file
        self._ensure_bucket_exists()
        self._initialize_csv()
        self.audit_log = []
        self.data_store = {}  # Maintained for backward compatibility
        self.keys = {}  # For revocation functionality

    def _ensure_bucket_exists(self):
        try:
            self.s3.head_bucket(Bucket=self.s3_bucket_name)
            print(f"Bucket '{self.s3_bucket_name}' exists")
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                self.s3.create_bucket(
                    Bucket=self.s3_bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': 'ap-south-1'}
                )
                print(f"Created bucket '{self.s3_bucket_name}'")
            else:
                print(f"Bucket error: {e}")
                raise

    def _initialize_csv(self):
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['admin', 's3_key', 'allowed_roles', 'upload_time'])
                # Sample data as in your original
                writer.writerow(['bob', 'Bob/test.txt', 'BCS,BCY,BCD', '2025-04-01T16:49:22.656298'])

    def upload_file(self, owner, file_path, allowed_roles):
        try:
            with open(file_path, 'rb') as f:
                s3_key = f"{owner}/{os.path.basename(file_path)}"
                self.s3.put_object(
                    Bucket=self.s3_bucket_name,
                    Key=s3_key,
                    Body=f,
                    ServerSideEncryption='AES256'
                )
                self._update_csv(owner, s3_key, allowed_roles)
                self.data_store[owner] = s3_key  # Maintain compatibility
                self.audit_log.append(f"Uploaded {s3_key} by {owner}")
                return True
        except Exception as e:
            print(f"Upload failed: {e}")
            return False

    def _update_csv(self, owner, s3_key, allowed_roles):
        with open(self.csv_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                owner.lower(),
                s3_key,
                ','.join(allowed_roles),
                datetime.now().isoformat()
            ])

    def access_file(self, user, user_role, owner):
        """Retrieve a file from S3 if the user has access"""
        try:
            # Check if the user has access based on the CSV file
            with open(self.csv_file, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if row['admin'].lower() == owner.lower():
                        required_roles = row['allowed_roles'].split(',')
                        if user_role not in required_roles:  # Check if the role is not allowed
                            print(f"❌ Access denied for {user} with role {user_role}")
                            return None
                        s3_key = row['s3_key']  # Retrieve the correct S3 key
                        break
                else:
                    print(f"❌ Access denied: No matching owner found for {owner}")
                    return None

            # Attempt to retrieve the file from S3
            response = self.s3.get_object(Bucket=self.s3_bucket_name, Key=s3_key)
            self.audit_log.append(f"File accessed by {user} with role {user_role}")
            print(f"✅ File '{s3_key}' accessed by {user}")
            return response['Body'].read()
        except Exception as e:
            print(f"Failed to access file: {e}")
            return None

    

    def download_from_s3(self, s3_key):
        """Download a file from S3"""
        try:
            response = self.s3.get_object(Bucket=self.s3_bucket_name, Key=s3_key)
            print(f"✅ File '{s3_key}' downloaded from S3.")
            return response['Body'].read()
        except Exception as e:
            print(f"❌ Failed to download file from S3: {e}")
            return None

    def _get_s3_key(self, owner):
        """Retrieve the S3 key for the specified owner from the CSV file."""
        try:
            with open(self.csv_file, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    if row['admin'].lower() == owner.lower():
                        return row['s3_key']  # Return the S3 key if the owner matches
            print(f"❌ No S3 key found for owner: {owner}")
            return None
        except Exception as e:
            print(f"❌ Failed to retrieve S3 key: {e}")
            return None

    def generate_user_key(self, name, attributes):
        """Maintain original method signature"""
        return {
            'user_id': name.lower(),
            'attributes': attributes,
            'requested_owner': None
        }

    def check_access_policy(self, user_key, policy):
        """Maintain original ABE-like interface"""
        required_roles = policy.split(',')
        user_roles = user_key['attributes'].split(',')
        return any(role in user_roles for role in required_roles)

    def get_audit_log(self):
        return self.audit_log

    def revoke_user(self, user_id):
        """Full revocation implementation"""
        for owner in self.keys:
            if user_id in self.keys[owner].get('revoked_users', []):
                self.keys[owner]['revoked_users'].append(user_id)
                self.audit_log.append(f"User {user_id} revoked by {owner}")

    def trace_user(self, leaked_key):
        """Full tracing implementation"""
        for owner in self.keys:
            if leaked_key in self.keys[owner].get('revoked_users', []):
                return owner
        return None

class DataOwner:
    def __init__(self, name, cloud_system):
        self.name = name
        self.cloud = cloud_system

    def upload_data(self, file_path, policy):
        """Maintain original interface"""
        allowed_roles = policy.split(',')
        return self.cloud.upload_file(self.name, file_path, allowed_roles)

    def revoke_access(self, user_id):
        self.cloud.revoke_user(user_id)

class CloudUser:
    def __init__(self, name, attributes, cloud_system):
        self.name = name
        self.cloud = cloud_system
        self.attributes = attributes
        self.user_key = self.cloud.generate_user_key(name, attributes)

    def request_access(self, owner):
        """Maintain original dual-path access checking"""
        # Method 1: Direct check
        s3_key = self.cloud._get_s3_key(owner)
        if s3_key:
            return self.cloud.download_from_s3(s3_key)
        
        # Method 2: Policy-based check (maintains original interface)
        self.user_key['requested_owner'] = owner
        with open(self.cloud.csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['admin'].lower() == owner.lower():
                    if self.cloud.check_access_policy(self.user_key, row['allowed_roles']):
                        return self.cloud.download_from_s3(row['s3_key'])
        return None

    def get_credentials(self):
        return self.user_key

class Authority:
    def __init__(self, cloud_system):
        self.cloud = cloud_system

    def revoke_user(self, user_id):
        self.cloud.revoke_user(user_id)

    def detect_leak(self, leaked_key):
        return self.cloud.trace_user(leaked_key)

    def audit_access(self):
        return self.cloud.get_audit_log()

class Auditor:
    def __init__(self, cloud_system):
        self.cloud = cloud_system
    
    def audit_access(self):
        return [f"Log: {log}" for log in self.cloud.get_audit_log()]