import base64
import json
from urllib.parse import unquote
from string import digits, ascii_letters, punctuation
from Crypto.Cipher import AES  # 需要安裝 pycryptodome


def cbc_encrypt(plaintext: str, key: str, iv: str):

    block_size = len(key)
    padding = (block_size - len(plaintext) % block_size) or block_size  # 填充

    mode = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    ciphertext = mode.encrypt((plaintext + padding * chr(padding)).encode())

    return base64.b64encode(ciphertext).decode()


def cbc_decrypt(ciphertext: str, key: str, iv: str):

    ciphertext = base64.b64decode(ciphertext)
    mode = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    plaintext = mode.decrypt(ciphertext).decode()
    return plaintext


if __name__ == '__main__':
    key = "Enter your key"
    iv = "Enter your iv"

    data = {
        "key_1": "value_1",
        "key_2": "value_2"
    }

    # 加密
    ciphertext = cbc_encrypt(json.dumps(data, separators=(',', ':')), key, iv)
    print(ciphertext)

    #ciphertext = ''
    # 解密
    plaintext = cbc_decrypt(unquote(ciphertext), key, iv)
    print(plaintext)