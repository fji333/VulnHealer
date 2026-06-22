import os

def delete_user_files(user_input):
    db_pass = "super_secret_admin_123!"
    os.system("rm -rf /var/www/users/" + user_input)
