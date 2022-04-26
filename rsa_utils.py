from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64
import os,sys

def encrypt(blob, public_key):
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    blob = zlib.compress(blob)

    #In determining the chunk size, determine the private key length used in bytes
    #and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =  b''

    while not end_loop:
        chunk = blob[offset:offset + chunk_size]

        #If the data chunk is less then the chunk size, then we need to add
        #padding with " ". This indicates the we reached the end of the file so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b' ' * (chunk_size - len(chunk))

        #Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size
    return base64.b64encode(encrypted)


def decrypt(encrypted_blob, private_key):
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)

    chunk_size = 512
    offset = 0
    decrypted = b''

    while offset < len(encrypted_blob):
        #The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]

        #Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        #Increase the offset by chunk size
        offset += chunk_size
    return zlib.decompress(decrypted)

def keys():
    #Generate a public/private key pair using 4096 bits
    new_key = RSA.generate(4096, e=65537)
    #The private key in PEM format
    private_key = new_key.exportKey("PEM")

    #The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")
    return public_key,private_key

