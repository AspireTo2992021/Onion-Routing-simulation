from ctypes import sizeof
from encodings import utf_8
import hashlib
import json
from pickle import EMPTY_LIST
import rsa 
from rsa.key import PrivateKey , PublicKey
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def main():
        
       

        #publickey , privatekey  = rsa.newkeys(512)
        publickey = PublicKey(8928429708723078367968408861159334506063110426565729327112925060107811252957539657740519188800753824003801730358296590317594677676593972782731522508866801, 65537)
        privatekey = PrivateKey(8928429708723078367968408861159334506063110426565729327112925060107811252957539657740519188800753824003801730358296590317594677676593972782731522508866801, 65537, 7980915653698145733743157726237638799978472237195379029264833237274147403585013383151331546783311427120008301328966463986393148773098771649605914910996385, 7374407942153548754663164198054381032220371048027587764755178234877068538757363637, 1210731733145170777170546913627385186032517448732030360185540371933504973)
        #print(publickey , privatekey)
        mes = "hello world!!!".encode()
        print(type(mes))
        #print(f"encoded text = {mes} ")
        em = rsa.encrypt(mes, publickey)
        print(f"cipher text = {em} type {type(em)}")

        dm =  rsa.decrypt(em, privatekey)
        edm = dm.decode()
        print(f"decr. cipher text = {dm}")
        print(f"type {type(dm)}")
        print(f"decoded text = {edm} ")
  


def value():
    pub1 =PublicKey(7983917926935097392867058539732667331427421537974849155220569811496754612796121898904241148472196691743961015145101173105911925316181035331152504859760807, 65537)
    pk1 = PrivateKey(7983917926935097392867058539732667331427421537974849155220569811496754612796121898904241148472196691743961015145101173105911925316181035331152504859760807, 65537, 3074083112871816647261964313160720317396883517543637084133174521618461415386561099470529348837144397417144476521624834424249700356166905754811972671006145, 4720150795683101730238177568807087573048537079709799195659042965328069120166036983, 1691453996392855123034860382026907012724714908770948385353281044480530129)
    
    pub2 = PublicKey(7290270068395828899710148486169906723087412314634344843168288741403642233077822455080861541378948203798928994951263833047935982555994871168496939091239457, 65537)
    pk2 = PrivateKey(7290270068395828899710148486169906723087412314634344843168288741403642233077822455080861541378948203798928994951263833047935982555994871168496939091239457, 65537, 235492954129636232672938711647186971218945814884430291789176606581801281689888138759343987987957121791441561569629141485502573947706328028056009488800193, 4400354834212435407369748150068708129514078740798940795906309546634711931347524121, 1656745954147723487435603189202520450994681446068282575372374193446361417)
    
    pub3 =  PublicKey(10979891451120946218354032207205278340203846797067479032558257023484227765458873464537111850075248756552352734092609171595765422426996680198096369846884609, 65537)
    pk3 = PrivateKey(10979891451120946218354032207205278340203846797067479032558257023484227765458873464537111850075248756552352734092609171595765422426996680198096369846884609, 65537, 8537197745926271517595654655882316376730204636131765705816120712661333199045650792215300486239673582762215232355890692421900025572261847728983485963417713, 7430441334609666845552243752496371612365998894471334915600282764385919455753391589, 1477690349290367925862851626605076271801235225002247704798687291086163181)

    m = "hello world".encode()

    em = rsa.encrypt(m,pub1)
    print(f"encryption 1 layer {em}")
    em = str(em).encode()
    em = rsa.encrypt(em,pub2)
    print(f"encryption 2 layer {em}")
    em = str(em).encode()
    em = rsa.encrypt(em,pub3)
    print(f"encryption 1 layer {em}")
    print(f"size of em {len(em)}")
    

    em =  rsa.decrypt(em, pk3)
    print(f"removing one layer {em}")
    em = eval(em)
    em =  rsa.decrypt(em, pk2)
    em = eval(em)
    em =  rsa.decrypt(em, pk1)
    em.decode()
    print(em)

def aes():

    data = b'secret data'

    key = get_random_bytes(16)
    print(f"key {key}")
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    print(f"nonce is  {nonce}")
    ciphertext, tag = cipher.encrypt_and_digest(data)
    #print(f"cipher tet {ciphertext} type {type(ciphertext)}")


    l = list()
    l.append(ciphertext)
    l.append(nonce)
    l.append(tag)
    l=str(l).encode()

    l = l.decode()
    l = eval(l)
    ciphertext = l[0]
    nonce = l[1]
    tag=l[2]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    print(data)

#aes()

def multilayer_aes():
    data = b'secret da'
    #key1 = get_random_bytes(16)
    key1=b'\x8a\x03\xca\xa4P=\xeb\xf8\x0ez\x10\xd7PX\xa5\xf2'
    cipher = AES.new(key1, AES.MODE_EAX)
    nonce1 = cipher.nonce
    #print(f"nounce is : {nonce1}")
    ciphertext, tag = cipher.encrypt_and_digest(data)


    #key2 = get_random_bytes(16)
    key2 = b'<\xfd\x98%\x1b\xd0\x05\xf4\x9c\xe4WV\x18\x90R\x7f'
    cipher = AES.new(key2, AES.MODE_EAX)
    nonce2 = cipher.nonce
    ciphertext, tag2 = cipher.encrypt_and_digest(ciphertext)


    #key3 = get_random_bytes(16)
    key3 = b'B\x87\xb9O\x85\xba\xad\x07\xa9j\x0f\xca\x17\x86/\xe6'
    cipher = AES.new(key3, AES.MODE_EAX)
    nonce3 = cipher.nonce
    print("nonce: ",nonce3)
    ciphertext, tag3 = cipher.encrypt_and_digest(ciphertext)





    cipher = AES.new(key3, AES.MODE_EAX, nonce3)
    ciphertext = cipher.decrypt_and_verify(ciphertext, tag3)
     
    

    cipher = AES.new(key2, AES.MODE_EAX, nonce2)
    ciphertext = cipher.decrypt_and_verify(ciphertext, tag2)

    cipher = AES.new(key1, AES.MODE_EAX, nonce1)
    ciphertext = cipher.decrypt_and_verify(ciphertext, tag)

    print(ciphertext)


#multilayer_aes()


#key = get_random_bytes(16)
#print(key)

k = str(list("hello world")).encode()
print(k)
#k = eval(k)
print(eval(k))
