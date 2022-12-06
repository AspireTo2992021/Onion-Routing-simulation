import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import threading

HOST = '192.168.56.1'
PORT = 8092
#HOST2= #WHATEVER IS THE NEXT SERVERS IP
#HOST_NEXT = '192.168.0.6'
HOST_NEXT='192.168.56.1'
PORT_NEXT = 8093



key_list = [b'\x8a\x03\xca\xa4P=\xeb\xf8\x0ez\x10\xd7PX\xa5\xf2']



#connect to next server
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
        print(data)
        print(type(data))
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

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST,PORT))
server.listen(5)
communication_socket , address =  server.accept()


server_next = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
server_next.connect((HOST_NEXT , PORT_NEXT))

"""
while True:
   #recive from client
   print(f" connected to {address}")
   message = communication_socket.recv(1024).decode('utf-8')
   message=decrypt(message)
   print(f"message form client {message}")

   #forward to next_server
   server_next.send(message.encode('utf-8'))

   #message reciverd from next server
   m=server_next.recv(1024).decode('utf-8')
   m=encrypt(m)
   # forward to client
   communication_socket.send(m.encode('utf-8'))
"""

# SERVER SIDE
def forward_to_next_server(): #listen client channel
    while True:
            #recive from client
            print(f" connected to {address}")
            message = communication_socket.recv(1024*10)
            message=decrypt(message)
            print(f"message form client {message}")

            #forward to next_server
            server_next.send(message.encode('utf-8'))
    

# client side

def forward_to_client() : 
 while True:
   #message reciverd from next server
   m=server_next.recv(1024).decode('utf-8')
   m=encrypt(m)
   # forward to client
   communication_socket.send(m.encode('utf-8'))





threading.Thread(target = forward_to_next_server ).start()
threading.Thread(target = forward_to_client ).start()



