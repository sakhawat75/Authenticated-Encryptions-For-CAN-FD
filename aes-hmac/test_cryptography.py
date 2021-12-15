

import json
from Crypto.Cipher import AES
import hmac
import hashlib



block_size = AES.block_size
block_size = 48

def __pad(plain_text):
    number_of_bytes_to_pad = block_size - len(plain_text) % block_size
    ascii_string = chr(number_of_bytes_to_pad)
    padding_str = number_of_bytes_to_pad * ascii_string
    padded_plain_text = plain_text + padding_str
    return padded_plain_text

def __unpad(plain_text):
        last_character = plain_text[len(plain_text) - 1:]
        bytes_to_remove = ord(last_character)
        return plain_text[:-bytes_to_remove]


with open("shared_key_group_1.json") as f:
    security_keys = json.load(f)

cipher = AES.new(security_keys['aes-128'][:16], AES.MODE_ECB)
stmsg = '12345678901234567890123456789012345678901234567'
print(f"Plain msg {stmsg}   len {len(stmsg)}")
msg = __pad(stmsg)
print(f"Paddi msg {msg}   len {len(msg)}")
msg = cipher.encrypt(msg)
print(f"Encry msg {msg}   len {len(msg)}")


decipher = AES.new(security_keys['aes-128'][:16], AES.MODE_ECB)
decmsg = decipher.decrypt(msg)
print(f"Decrp msg {decmsg}   len {len(decmsg)}")
decunpadmsg = __unpad(decmsg)
print(f"Nupad msg {decunpadmsg}   len {len(decunpadmsg)}")





dig = hmac.new(security_keys['aes-128'][:32].encode(), msg=msg, digestmod=hashlib.sha256).digest()
print(f"HMAC {dig}    len {len(dig)}")
