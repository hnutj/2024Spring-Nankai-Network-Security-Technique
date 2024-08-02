import socket
import threading
import os
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher,modes,algorithms
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding 
from cryptography.x509 import Certificate, DNSName, load_pem_x509_certificate
from cryptography.x509.verification import PolicyBuilder, Store

import base64
import datetime
from tkinter import *

#listen for the messages
class SubThread_chat(threading.Thread):
    def run(self):
        global thelist,aes_fernet,choice,pk_partner,ecc_pk_partner,associ_key
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.bind(('127.0.0.1', 999))
        s1.listen(10)
        sock, addr = s1.accept()

        while True:
            #extinguish the received data
            data=sock.recv(4096)
            info, signature = data.split(b"signatureofenc_data")
            #verify the signature
            pk_partner.verify(
                signature,
                info,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            #decrypt info in diff ways
            if choice.get()==0:
                #des
                info=des_decryptor.update(info)+des_decryptor.finalize()
                unpadder = PKCS7(algorithms.TripleDES.block_size).unpadder()
                info = unpadder.update(info)+unpadder.finalize()
            elif choice.get()==1:
                #aes
                info =aes_fernet.decrypt(info)
            elif choice.get()==2:
                #rsa
                info= private_key.decrypt(
                    info,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            elif choice.get()==3:
                #ecc
                info = aes_fernet.decrypt(info)
            #decode the info
            thelist.insert(END, 'ta:' + info.decode())

#listen for the algorithm changing
class SubThread_assoKey(threading.Thread):
    def run(self):
        s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s3.bind(('127.0.0.1', 888))

        while True:
            global choice,pk_partner,associ_key,aes_fernet
            s3.listen(10)
            sock, addr = s3.accept()
            #change encrypt ways
            sig=sock.recv(4096)
            if sig:
                choice.set(int(sig.decode())) 


#send signed enc_messages     
def send():
    #encrypt with diff ways
    global v,aes_fernet,pk_partner,choice,s2
    if choice.get()==0:
        #des
        data=v.get().encode()
        padder = PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        enc_data=des_encryptor.update(padded_data)+des_encryptor.finalize()
    elif choice.get()==1:
        #aes
        enc_data=aes_fernet.encrypt(v.get().encode())
    elif choice.get()==2:
        #rsa
        enc_data = pk_partner.encrypt(
                v.get().encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
        )
    elif choice.get()==3:
        #ecc
        enc_data=aes_fernet.encrypt(v.get().encode())
    #sign the enc_messages
    signature = private_key.sign(
        enc_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    msg=enc_data+b"signatureofenc_data"+signature
    s2.send(msg)
    global thelist
    thelist.insert(END, 'me:' + v.get())
    v.set('')

#event for changing encrypt mode:des aes rsa ecc
def associate_key():
    s4 = socket.socket()
    s4.connect(('127.0.0.1', 222))
    sig=str(choice.get()).encode()
    s4.send(sig)

#generate certifi
def gen_cert():
    # Generate our key
    au_privkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Write our key to disk for safe keeping
    with open("./pyCryptoChat/info_attached/key1.pem", "wb") as f:
        f.write(au_privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"), 
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,  "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            au_privkey.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.now() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
    # Sign our certificate with our private key
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(au_privkey, hashes.SHA256())
    # Write our certificate out to disk.
    with open("./pyCryptoChat/info_attached/certificate1.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

#verify partner's certifi
def veri_cert():
    with open("./pyCryptoChat/info_attached/certificate2.pem", "rb") as f:
        cert=load_pem_x509_certificate(f.read())
        # Verify the certificate
    try:
        cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding=cert.signature_algorithm_parameters,
            algorithm=cert.signature_hash_algorithm,
        )
        print("Certificate verification successful.")
    except Exception as e:
        print("Certificate verification failed:", e)

def connect_with_retry(host, port, max_attempts=10, retry_interval=5):
    attempts = 0
    while attempts < max_attempts:
        try:
            # 创建套接字对象
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 设置连接超时时间为 30 秒
            s.settimeout(30)
            # 尝试连接到远程主机
            s.connect((host, port))
            print("连接成功")
            return s
        except socket.error as e:
            print(f"连接失败: {e}")
            attempts += 1
            if attempts < max_attempts:
                print(f"重试中，尝试次数: {attempts}/{max_attempts}")
                time.sleep(retry_interval)
            else:
                print("已达到最大尝试次数，无法连接到远程主机")
                raise

if __name__ == '__main__':
    gen_cert()
    #triple-des key
    des_key =b"\\\xfd\xcf'iF+\xe8W\x04\xc7\xdc\x14\x8e^>\xc8e\x90\x15\xb0\t\xbeF"
    iv=b'\x1d\xb8\xc5\x85n\xc4B\xf7'
    cipher = Cipher(TripleDES(des_key), mode=modes.CBC(iv),backend=default_backend())
    des_encryptor = cipher.encryptor()
    des_decryptor=cipher.decryptor()
    #aes key
    aes_fernet = None
    #rsa key
    private_key= rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    with open("./pyCryptoChat/info_attached/client_rsa_privkey.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b'rsaprivkey')
            )
        )
    with open("./pyCryptoChat/info_attached/client_rsa_pubkey.pem", "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    pk_partner=None
    #ecc key
    ecc_private_key = ec.generate_private_key(ec.SECP384R1())
    with open("./pyCryptoChat/info_attached/client_ecc_pubkey.pem", "wb") as f:
        f.write(
            ecc_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    ecc_pk_partner=None
    associ_key=None

    #ui
    root = Tk()
    v = StringVar()
    main_menu=Menu(root)
    enc_menu=Menu(main_menu,tearoff=False)
    choice=IntVar()
    choice.set(1)
    enc_menu.add_radiobutton(label="DES",variable=choice,value=0,command=associate_key)
    enc_menu.add_radiobutton(label="AES",variable=choice,value=1,command=associate_key)
    enc_menu.add_radiobutton(label="RSA",variable=choice,value=2,command=associate_key)
    enc_menu.add_radiobutton(label="ECC",variable=choice,value=3,command=associate_key)
    main_menu.add_cascade(label="encrypt",menu=enc_menu)
    root.config(menu=main_menu)
    thebutton = Button(root, text="send", command=send)
    thebutton.grid(row=11, column=5)
    thelist = Listbox(root)
    thelist.grid(row=0, column=1, rowspan=10, columnspan=5)
    thelist.insert(END, '2nd tk')
    theentry = Entry(root, textvariable=v)
    theentry.grid(row=11, column=1, columnspan=4)

    #thread
    p1 = SubThread_chat()
    p2=SubThread_assoKey()
    p1.start()
    p2.start()
    s2=connect_with_retry('127.0.0.1', 111)
    #verification of certifi
    veri_cert()
    #get partner's pubkey for encrypt and verify
    with open("./pyCryptoChat/info_attached/server_rsa_pubkey.pem", "rb") as key_file:
        pk_partner = serialization.load_pem_public_key(
            key_file.read(),
        ) 
    with open("./pyCryptoChat/info_attached/server_ecc_pubkey.pem", "rb") as key_file:
        ecc_pk_partner = serialization.load_pem_public_key(
            key_file.read(),
        ) 
    shared_key = ecc_private_key.exchange(
        ec.ECDH(), ecc_pk_partner)
    # Perform key derivation.
    associ_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)  
    aes_fernet=Fernet(base64.urlsafe_b64encode(associ_key))
    print(aes_fernet._encryption_key)
    mainloop()