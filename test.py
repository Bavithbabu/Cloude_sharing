# from cpab import DataOwner, CloudUser, Auditor
from cpab import IntegratedCloudSystem
import boto3


class IntegratedCloudSystem:
    def __init__(self, s3_bucket_name):
        self.s3 = boto3.client('s3', region_name='ap-south-1')
        self.s3_bucket_name = s3_bucket_name
        self._ensure_bucket_exists()
        self.data_store = {}
        self.roles = {"admin": ["doctor"], "staff": ["nurse", "receptionist"]}
        self.audit_log = []  # Initialize the audit log

    def _ensure_bucket_exists(self):
        """Ensure the S3 bucket exists, create it if it does not."""
        try:
            self.s3.head_bucket(Bucket=self.s3_bucket_name)
        except self.s3.exceptions.NoSuchBucket:
            self.s3.create_bucket(
                Bucket=self.s3_bucket_name,
                CreateBucketConfiguration={'LocationConstraint': 'ap-south-1'}
            )
        except Exception as e:
            print(f"Error ensuring bucket exists: {e}")
            raise

    # def upload_file(self, owner, file_path, allowed_roles):
    #     """Upload a file to the S3 bucket."""
    #     try:
    #         with open(file_path, 'rb') as file_data:
    #             s3_key = f"{owner}/{file_path.split('/')[-1]}"
    #             self.s3.put_object(
    #                 Bucket=self.s3_bucket_name,
    #                 Key=s3_key,
    #                 Body=file_data,
    #                 ServerSideEncryption='AES256'
    #             )
    #             self.data_store[owner] = (s3_key, allowed_roles)
    #             self.audit_log.append(f"File '{s3_key}' uploaded by {owner} with roles {allowed_roles}")
    #             return True
    #     except Exception as e:
    #         print(f"Upload failed: {e}")
    #         return False
    def upload_file(self, owner, file_path, allowed_roles):
        """Upload a file to S3 and update the local MySQL database."""
        try:
            with open(file_path, 'rb') as file_data:
                s3_key = f"{owner}/{file_path.split('/')[-1]}"
                self.s3.put_object(
                    Bucket=self.s3_bucket_name,
                    Key=s3_key,
                    Body=file_data,
                    ServerSideEncryption='AES256'
                )
                
                # Update MySQL after successful upload
                self._update_db_after_upload(owner, s3_key, allowed_roles)
                
                print(f"✅ File '{s3_key}' uploaded successfully.")
                return True
        except Exception as e:
            print(f"❌ Upload failed: {e}")
            return False

    def _update_db_after_upload(self, owner, s3_key, allowed_roles):
        """Update the local MySQL database after an admin uploads a file."""
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO file_access (admin, s3_key, allowed_roles) VALUES (%s, %s, %s)",
                (owner.lower(), s3_key, ','.join(allowed_roles))
            )
            
            conn.commit()
            conn.close()
            print(f"📂 File metadata stored in local database for '{s3_key}'.")
        except Exception as e:
            print(f"❌ Database update failed: {e}")


    def access_file(self, user, role, owner):
        """Retrieve a file from the S3 bucket if the user has access."""
        print(self.data_store)
        if owner not in self.data_store:
            print(f"❌ No data found for owner: {owner}")
            return None
        
        s3_key, allowed_roles = self.data_store[owner]
        if role not in allowed_roles:
            print(f"❌ Access denied for user: {user} with role: {role}")
            return None
        
        try:
            response = self.s3.get_object(Bucket=self.s3_bucket_name, Key=s3_key)
            print(f"✅ File '{s3_key}' accessed by {user}")
            return response['Body'].read()
        except Exception as e:
            print(f"❌ Failed to access file: {e}")
            return None

    def get_audit_log(self):
        """Return the audit log."""
        return self.audit_log

class CloudUser:
    def __init__(self, name, role, cloud_system):
        self.name = name
        self.role = role
        self.cloud = cloud_system

    def request_access(self, owner):
        """Request access to a file owned by another user."""
        return self.cloud.access_file(self.name, self.role, owner)

class Auditor:
    def __init__(self, cloud_system):
        self.cloud = cloud_system

    def audit_access(self):
        """Retrieve the audit log from the cloud system."""
        return self.cloud.get_audit_log()

def test_full_system_with_s3():
    """Interactive Testing for CP-ABE + S3 Integration"""
    print("\n=== 🔍 CP-ABE + S3 Role-Based Access Test ===\n")
    
    cloud = IntegratedCloudSystem("cpab-medical")
    user_type = input("Are you an Admin or a User? (admin/user): ").strip().lower()
    
    if user_type == "admin":
        admin_name = input("Enter Admin Name: ").strip()
        allowed_roles = input("Enter allowed roles (comma-separated): ").strip().split(",")
        file_path = input("Enter the file path to upload: ").strip()
        file_name = file_path.split("/")[-1]
        
        # Directly call the upload_file method
        upload_success = cloud.upload_file(admin_name, file_path, allowed_roles)
        
        if upload_success:
            print(f"✅ Data uploaded successfully by {admin_name}")
        else:
            print(f"❌ Failed to upload data by {admin_name}")
    
    elif user_type == "user":
        admin_name = input("Enter Admin Name: ").strip()
        user_name = input("Enter your name: ").strip()
        user_role = input("Enter your role: ").strip()
        
        staff = CloudUser(user_name, user_role, cloud)
        
        print(f"\n{user_name} attempting to access {admin_name}'s file...")
        access_result = staff.request_access(admin_name)

        if access_result:
            print("✅ Access granted. File downloaded from S3.")
        else:
            print("❌ Access denied.")
    
    auditor = Auditor(cloud)
    print("\n🔎 Audit Log:")
    print("\n".join(auditor.audit_access()))

if __name__ == "__main__":
    test_full_system_with_s3()

 