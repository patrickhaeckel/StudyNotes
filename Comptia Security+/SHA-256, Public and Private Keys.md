---
title: SHA-256, Public and Private Keys
updated: 2024-12-17 18:24:46Z
created: 2024-09-06 00:03:00Z
---

When a password is stored as a hash using a cryptographic function like SHA-256, the original password cannot be recovered from the hash. However, operating systems or authentication systems don't need to reverse the hash to authenticate you. Here's how it works:

1.  **Initial Setup (Registration/Password Change):**
    
    - When you create a password, the system takes your plain text password and hashes it using a function like SHA-256.
    - The resulting hash is then stored in a database.
2.  **Authentication (Login):**
    
    - When you try to log in, you enter your password again.
    - The system takes the password you provided and hashes it using the same SHA-256 function.
    - It then compares the newly generated hash to the hash stored in the database.
3.  **Comparison:**
    
    - If the two hashes match, it means the password you entered is correct, so the system authenticates you.
    - If they don't match, access is denied.

**Why This Works:**

- **Hash Functions are Deterministic:** The same input (your password) will always produce the same hash output. This allows the system to verify the password without ever needing to store or retrieve the actual password.
    
- **Security:** Even if the hashed password is exposed, an attacker cannot easily reverse it to find the original password due to the one-way nature of cryptographic hash functions like SHA-256.
    

**Additional Measures:**

- **Salting:** To further protect against attacks like rainbow tables (precomputed tables of hash values), systems often add a random value called a "salt" to the password before hashing. The salt is unique for each password and is stored alongside the hash. During authentication, the salt is combined with the entered password before hashing to ensure that even if two users have the same password, their hashes will be different.

This process ensures that passwords can be securely stored and verified without the need to reverse the hash.

### How It Works in SSH Authentication

1.  **Public Key Encryption**:
    
    - During SSH authentication, the server uses the client’s public key to encrypt a challenge (often a random number or string).
2.  **Private Key Decryption**:
    
    - The client, which has the corresponding private key, uses that private key to decrypt the challenge sent by the server.
    - If the client can successfully decrypt the challenge, it proves that the client possesses the correct private key, thus authenticating the client to the server.  

### Relationship Between Public and Private Keys

- **Key Pair Generation**:
    - When you generate a key pair, both the **public key** and the **private key** are created simultaneously. These two keys are mathematically linked.
    - The private key is used to generate the public key, meaning the public key is derived from the private key using specific mathematical algorithms. However, the process is one-way: you cannot derive the private key from the public key.

### Encryption and Decryption

- **Asymmetric Encryption**:
    
    - This type of encryption involves two keys: one for encryption and another for decryption. The public key and private key work together in this asymmetric system.
- **Public Key**:
    
    - The public key is used to encrypt data. Anything encrypted with the public key can only be decrypted by the corresponding private key.
- **Private Key**:
    
    - The private key is used to decrypt data that was encrypted with the corresponding public key.