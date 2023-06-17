from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


def encrypt_with_pub_key(a_message):
    with open('runtime/certs/cred_store_pub.pem') as outfile:
        pub_key_raw = outfile.read()
    pub_key = RSA.importKey(pub_key_raw)
    message = str(a_message).encode()
    if len(message) > 100:
        encoded_encrypted_msg = rsa_long_encrypt(pub_key, message)
    else:
        encryptor = PKCS1_OAEP.new(pub_key)
        encrypted_msg = encryptor.encrypt(message)
        encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg

def decrypt_with_priv_key(encoded_encrypted_msg):
    with open('runtime/certs/cred_store_pri.pem') as outfile:
        priv_key_raw = outfile.read()
    priv_key = RSA.importKey(priv_key_raw)
    if len(encoded_encrypted_msg) > 100:
        decoded_decrypted_msg = rsa_long_decrypt(priv_key, encoded_encrypted_msg)
    else:
        decryptor = PKCS1_OAEP.new(priv_key)
        decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
        decoded_decrypted_msg = decryptor.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg.decode('utf-8')

def rsa_long_encrypt(pub_obj, msg, length=100):
    """The maximum length of a single encrypted string is (key_size/8) -11 100 for 1024bit certificates and 200 for 2048bit certificates"""
    encryptor = PKCS1_OAEP.new(pub_obj)
    res = []
    for i in range(0, len(msg), length):
        res.append(encryptor.encrypt(msg[i:i + length]))
    encrypted_msg = b''.join(res)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg



def rsa_long_decrypt(priv_obj, msg, length=256):
    """128 for 1024bit certificates and 256 bits for 2048bit certificates"""
    decryptor = PKCS1_OAEP.new(priv_obj)
    msg = base64.b64decode(msg)
    res = []
    for i in range(0, len(msg), length):
        res.append(decryptor.decrypt(msg[i:i + length]))
    decoded_decrypted_msg = b''.join(res)
    return decoded_decrypted_msg

