import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


HOST = '192.168.56.1'
#HOST='localhost'
PORT = 8093
key_list = [b'\x8a\x03\xca\xa4P=\xeb\xf8\x0ez\x10\xd7PX\xa5\xf2',b'<\xfd\x98%\x1b\xd0\x05\xf4\x9c\xe4WV\x18\x90R\x7f',b'B\x87\xb9O\x85\xba\xad\x07\xa9j\x0f\xca\x17\x86/\xe6']


#public_key , private_key = rsa.newkeys(1024)
#public_partner = None

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST,PORT))
server.listen(5)
communication_socket , address =  server.accept()

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
        



while True:
    
    print(f" connected to {address}")
    message = communication_socket.recv(1024*10)
    #print(f"message form client {message}")
    
    
    print(f"decrypted message form client {decrypt(message).decode()}")

    communication_socket.send(input("Enter message for client").encode('utf-8'))
    #communication_socket.close()
    print(f"connection with {address} ended !!")

"""while True:
    
    print(f" connected to {address}")
    message = communication_socket.recv(1024).decode('utf-8')
    print(f"message form client {message}")

    l = eval(message)
    ciphertext = l[0]
    nonce = l[1]
    tag = l[2]
    cipher = AES.new(key[0], AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    print(f"decrypted message form client {data.decode()}")

    communication_socket.send(input("Enter message for client").encode('utf-8'))
    #communication_socket.close()
    print(f"connection with {address} ended !!")"""


