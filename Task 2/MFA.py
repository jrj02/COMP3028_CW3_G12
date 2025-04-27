import hashlib
import hmac
import time
import random
import string
import getpass
import os
import base64
import secrets
import pyotp

class MFASystem:
    def __init__(self, db_file="user_database.txt"): #function to initializea database
        self.db_file = db_file
        
        if not os.path.exists(db_file): #if if database no initialized yet, create a new one
            with open(db_file, 'w') as f:
                pass
    
    def hash_password(self, password, salt=None): #function to hash user's password
        if salt is None:  #If there is no salt, create one 
            salt = os.urandom(16) #16 bytes salt is generated (Random string added before hashing a password)

        # Hash the password with the salt
        hash_obj = hashlib.pbkdf2_hmac( #password-based key derivation function 2
            'sha256',                   #and sha256 to securely hash the password
            password.encode('utf-8'),
            salt,
            150000  #number of iterations
        )
        
        return salt, hash_obj
    
    def register_user(self, username, password): #function to register a new user
        if self.get_user_data(username): # Check if user already exists
            return False, "Username already exists" #If that user already exits, inform use that the username is taken
        
        salt, hashed_password = self.hash_password(password) #Hash the password with a salt
        
        otp_secret = self.generate_otp_secret() # Generate a secret key for OTP
        
        # Store user data
        user_data = {
            "username": username,
            "salt": salt.hex(),
            "hashed_password": hashed_password.hex(),
            "otp_secret": otp_secret
        }
        
        self.save_user_data(user_data) #save the user data to databse
        return True, otp_secret
    
    def save_user_data(self, user_data): #writing the data to save into user_database.txt
        with open(self.db_file, 'a') as f:
            f.write(f"{user_data['username']}:{user_data['salt']}:{user_data['hashed_password']}:{user_data['otp_secret']}\n")
    
    def get_user_data(self, username):
        if not os.path.exists(self.db_file): #if database does not exist then return none
            return None
        
        with open(self.db_file, 'r') as f: #read the user_database.txt to find a matching username
            for line in f:
                parts = line.strip().split(':')
                if len(parts) == 4 and parts[0] == username:
                    return {
                        "username": parts[0],
                        "salt": parts[1], 
                        "hashed_password": parts[2],
                        "otp_secret": parts[3] #return user details
                    }
        return None
    
    def verify_password(self, username, password): 
        user_data = self.get_user_data(username) 
        if not user_data:
            return False
        
        # Retrieve the salt and stored hash
        salt = bytes.fromhex(user_data["salt"])
        stored_hash = bytes.fromhex(user_data["hashed_password"])
        
        # Hash the provided password with the same salt
        _, calculated_hash = self.hash_password(password, salt)
        
        # Compare the hashes
        return hmac.compare_digest(calculated_hash, stored_hash)
    
    
    # Generates a cryptographically secure Base32-encoded secret key 
    # to simulate real life TOTP apps like Google Authenticator.
    
    # Default length is 20 bytes (~160 bits), recommended for TOTP.

    def generate_otp_secret(self, length=20):
        # Generate secure random bytes
        random_bytes = secrets.token_bytes(length)
        
        # Encode them using Base32 (RFC compliant)
        base32_secret = base64.b32encode(random_bytes).decode('utf-8')
        
        return base32_secret

        
    # Generate a TOTP (Time-based One-Time Password) using RFC 6238 standard.
    # This OTP is valid for 30 seconds by default.
    def generate_otp(self, secret):
        totp = pyotp.TOTP(secret)
        return totp.now()
        
    # Verify the provided OTP code against the current TOTP.
    # Allows for small time drift automatically.
    def verify_otp(self, secret, otp):
        totp = pyotp.TOTP(secret)
        return totp.verify(otp)

def simple_mfa_system(): #function to design a simple MFA system
    mfa = MFASystem()
    
    print("\n===== Simple MFA System =====")
    
    # Main menu
    while True:
        print("\nOptions:")
        print("1. Register a new user")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            # Register a new user
            username = input("Enter a username: ")
            password = getpass.getpass("Enter a password: ")
            
            success, result = mfa.register_user(username, password)
            
            if success:
                print(f"\nUser {username} registered successfully!")
                print(f"Your OTP secret is: {result}")
                print("In a real system, this would be provided to the user via a secure channel")
                print("or displayed as a QR code for scanning with an authenticator app.")
            else:
                print(f"\nRegistration failed: {result}")
                
        elif choice == '2':
            # Login
            username = input("Enter your username: ")
            password = getpass.getpass("Enter your password: ")
            
            # First factor: password verification
            if mfa.verify_password(username, password):
                print("\nPassword verified successfully! ✓")
                
                # Get the user's OTP secret
                user_data = mfa.get_user_data(username)
                if not user_data:
                    print("User not found")
                    continue
                
                otp_secret = user_data["otp_secret"]
                
                # In a real system, the user would get this from their authenticator app
                # For demo purposes, we'll generate and show it
                current_otp = mfa.generate_otp(otp_secret)
                print(f"\n[SIMULATION] OTP sent to your device: {current_otp}")
                
                # Second factor: OTP verification
                provided_otp = input("Enter the OTP code: ")
                
                if mfa.verify_otp(otp_secret, provided_otp):
                    print("\nOTP verified successfully! ✓")
                    print("\n=== LOGIN SUCCESSFUL ===")
                    print(f"Welcome back, {username}!")
                else:
                    print("\nInvalid OTP. Login failed.")
            else:
                print("\nInvalid username or password.")
                
        elif choice == '3':
            print("\nExiting MFA system. Goodbye!")
            break
        else:
            print("\nInvalid choice. Please try again.")


if __name__ == "__main__":
    simple_mfa_system()