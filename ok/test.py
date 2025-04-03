from cpab import IntegratedCloudSystem, CloudUser, Auditor
from datetime import datetime
from encryption import SecureCloudStorage  # Added for decryption verification

def test_full_system_with_s3():
    print("\n=== Cloud Storage Access Test ===\n")
    cloud = IntegratedCloudSystem("cpab-medical")
    secure_storage = SecureCloudStorage("my_secure_key")  # Same key as used in encryption
    
    user_type = input("Are you an Admin or User? (admin/user): ").lower().strip()
    
    if user_type == "admin":
        admin_name = input("Admin Name: ").strip()
        allowed_roles = input("Allowed roles (comma-separated): ").strip().split(",")
        file_path = input("File path to upload: ").strip()
        
        if cloud.upload_file(admin_name, file_path, allowed_roles):
            print("Upload successful!")
        else:
            print("Upload failed")
            
    elif user_type == "user":
        admin_name = input("Admin Name to access: ").strip()
        user_name = input("Your Name: ").strip()
        user_role = input("Your Role: ").strip()
        
        # First verify role against CSV records
        with open(cloud.csv_file, 'r') as f:
            reader = csv.DictReader(f)
            access_granted = False
            s3_key = None
            
            for row in reader:
                if row['admin'].lower() == admin_name.lower():
                    required_roles = [r.strip() for r in row['allowed_roles'].split(',')]
                    if user_role in required_roles:
                        access_granted = True
                        s3_key = row['s3_key']
                        break
            
            if not access_granted:
                print("❌ Access denied - Invalid role")
                return
        
        # Only proceed if role is valid
        user = CloudUser(user_name, user_role, cloud)
        encrypted_data = user.request_access(admin_name)
        
        if encrypted_data:
            try:
                # Verify decryption is only attempted by authorized users
                decrypted_data = secure_storage.decrypt(encrypted_data.decode('utf-8'))
                
                filename = f"downloaded_{admin_name}_file.txt"
                with open(filename, 'w') as f:
                    f.write(decrypted_data)
                print(f"✅ Access granted! File saved as: {filename}")
            except Exception as e:
                print(f"❌ Decryption failed: {str(e)}")
        else:
            print("❌ Access denied - No data returned")
    
    print("\nAudit Log:")
    auditor = Auditor(cloud)
    for log in auditor.audit_access():
        print(f"- {log}")
    
    print("\nCSV Contents:")
    with open(cloud.csv_file, 'r') as f:
        print(f.read())

if __name__== "__main__":
    test_full_system_with_s3()