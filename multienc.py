from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto import Random

def pkcs5pad(message):
    togo = AES.block_size - (len(message) % AES.block_size)
    return message + chr(togo)*togo

def pkcs5unpad(padded):
    num = ord(padded[-1])
    return padded[:-num]

def aes_encrypt(key, message):
    iv = Random.new().read(AES.block_size)
    message = pkcs5pad(message)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def aes_decrypt(key, ct):
    iv = ct[:AES.block_size]
    ct = ct[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return pkcs5unpad(cipher.decrypt(ct))

def rsa_encrypt(pub, message):
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(message)

def rsa_decrypt(priv, ct):
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(ct)

def rsa_importKey(fn):
    with open(fn) as f:
        return RSA.importKey(f.read())

def multi_encrypt(pubs, message):
    session_key = Random.new().read(32)
    ct = [aes_encrypt(session_key, message),]
    for pub in pubs:
        ct.append(rsa_encrypt(pub, session_key))
    return ct

def multi_decrypt(priv, ct):
    for enc_key in ct[1:]:
        try:
            session_key = rsa_decrypt(priv, enc_key)
        except ValueError:
            continue
        break
    else:
        raise ValueError('Incorrect decryption.')
    return aes_decrypt(session_key, ct[0])

def multi_add_parties(priv, pubs, ct):
    for enc_key in ct[1:]:
        try:
            session_key = rsa_decrypt(priv, enc_key)
        except ValueError:
            continue
        break
    else:
        raise ValueError('Incorrect decryption.')
    for pub in pubs:
        ct.append(rsa_encrypt(pub, session_key))
    return ct
