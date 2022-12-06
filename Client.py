import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HOST='192.168.56.1'
PORT = 8090

socket = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
socket.connect((HOST , PORT))
key_list = [b'\x8a\x03\xca\xa4P=\xeb\xf8\x0ez\x10\xd7PX\xa5\xf2',b'<\xfd\x98%\x1b\xd0\x05\xf4\x9c\xe4WV\x18\x90R\x7f',b'B\x87\xb9O\x85\xba\xad\x07\xa9j\x0f\xca\x17\x86/\xe6']


def encrypt(data):
    for key in key_list:
        cipher = AES.new(key, AES.MODE_EAX)
        nonce1 = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        l = list()
        l.append(ciphertext)
        l.append(nonce1)
        l.append(tag)
        data=str(l)
        #print(data)
        #print(type(data))
    return data

def decrypt(data):
    for key in reversed(key_list) :
        data = data.decode()
        l = eval(data)
        ciphertext = l[0]
        nonce = l[1]
        tag = l[2]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        #print(data)
        #print(type(data))
    return data



while True : 
        data = input("Enter Request: ")
        socket.send(encrypt(data).encode())
        m = socket.recv(1024*10)
        print( decrypt(m).decode() )