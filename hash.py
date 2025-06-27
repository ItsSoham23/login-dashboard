import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

print("Chaitanya:", hash_password("Chaitanya123"))
print("Aneesh:", hash_password("Aneesh123"))
print("Jayprakash:", hash_password("Jayprakash123"))
print("intern_user:", hash_password("intern2024"))
