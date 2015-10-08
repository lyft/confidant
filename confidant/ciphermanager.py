from cryptography.fernet import Fernet


class CipherManager:
    '''
    Class for encrypting and decrypting strings.

    cipher = CipherManager(key)
    encrypted_text = cipher.encrypt('hello world')
    decrypted_text = cipher.decrypt(encrypted_text)
    '''
    def __init__(self, key, version=2):
        self.key = key
        self.version = version

    def encrypt(self, raw):
        if self.version == 2:
            f = Fernet(self.key)
            return f.encrypt(raw.encode('utf-8'))
        else:
            raise CipherManagerError('Bad cipher version')

    def decrypt(self, enc):
        if self.version == 2:
            f = Fernet(self.key)
            return f.decrypt(enc.encode('utf-8'))
        else:
            raise CipherManagerError('Bad cipher version')


class CipherManagerError(Exception):
    pass
