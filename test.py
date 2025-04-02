from cpab import IntegratedCloudSystem, CloudUser, Auditor
from datetime import datetime

def test_full_system_with_s3():
    print("\n=== Cloud Storage Access Test ===\n")
    cloud = IntegratedCloudSystem("cpab-medical")
    
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
        
        user = CloudUser(user_name, user_role, cloud)
        data = user.request_access(admin_name)
        
        if data:
            filename = f"downloaded_{admin_name}_file.txt"
            with open(filename, 'wb') as f:  # 'wb' for binary write mode
                f.write(data)
            print(f"✅ Access granted! File saved as: {filename}")
        else:
            print("❌ Access denied")
    
    print("\nAudit Log:")
    auditor = Auditor(cloud)
    for log in auditor.audit_access():
        print(f"- {log}")
    
    print("\nCSV Contents:")
    with open(cloud.csv_file, 'r') as f:
        print(f.read())

if __name__ == "__main__":
    test_full_system_with_s3()