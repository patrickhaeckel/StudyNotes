---
title: Non Repudiation and Integrity
updated: 2024-12-29 04:46:59Z
created: 2024-12-29 04:45:49Z
---

- **Message Signing (Sender's Side)**:
    - The sender starts with their message and private key
    - They hash the message using a cryptographic hash function (like SHA-256): `H_message = Hash(message)`
    - They then encrypt the hash with their *private* key to create the signature: `Signature = Encrypt(H_message, PrivKey)`
    - They send both the original message and the signature to the recipient
- **Signature Verification (Recipient's Side)**:
    - The recipient receives both the message and the signature
    - They calculate the hash of the received message: `H_received = Hash(received_message)`
    - They decrypt the signature using the sender's *public* key: `H_original = Decrypt(Signature, PubKey)`
    - They compare `H_received` with `H_original`
        - If they match, the signature is valid - confirming both authenticity and integrity
        - If they don't match, either the message was altered or the signature is invalid  
            <br/>

**Authentication**: Only someone with the sender's private key could have created a valid signature  
**Integrity**: Any modification to the message would result in a different hash, causing the verification to fail

**The fundamental security principle here is that while anyone can verify the signature using the public key, only the holder of the private key can create valid signatures.**