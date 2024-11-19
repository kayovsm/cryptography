from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

# classe do algoritmo AES
class AESCipher:
    def __init__(self, password, salt_size=16, key_length=32):
        self.password = password
        self.salt_size = salt_size
        self.key_length = key_length

    # gera a chave de criptografia
    def _derive_key(self, salt):
        return PBKDF2(self.password, salt, dkLen=self.key_length)

    # criptografa o texto 
    def encrypt(self, plaintext):

        # deriva a chave de criptografia usando o salt
        salt = get_random_bytes(self.salt_size)
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce

        # criptografa o texto e gera o tag de autenticação
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        encrypted_data = salt + nonce + tag + ciphertext

        # codifica os dados criptografados em base64 e retorna como string
        return base64.b64encode(encrypted_data).decode()

    # descriptografa o texto
    def decrypt(self, encrypted_data):

        # decodifica os dados criptografados de base64
        encrypted_data = base64.b64decode(encrypted_data)

        # extrai o salt dos dados criptografados
        salt = encrypted_data[:self.salt_size]
        nonce = encrypted_data[self.salt_size:self.salt_size+16]
        tag = encrypted_data[self.salt_size+16:self.salt_size+32]
        ciphertext = encrypted_data[self.salt_size+32:]

        # deriva a chave de criptografia usando o salt
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        # descriptografa o texto e verifica o tag de autenticação
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # retorna o texto descriptografado como string
        return plaintext.decode()

senha = "senha"
texto = "Teste do algoritmo AES"

# criptografando
cipher = AESCipher(senha)
texto_criptografado = cipher.encrypt(texto)
print("Texto criptografado:", texto_criptografado)

# descriptografando
texto_descriptografado = cipher.decrypt(texto_criptografado)
print("Texto descriptografado:", texto_descriptografado)