from cryptography.fernet import Fernet

# Gerar chave pública e privada
key = Fernet.generate_key()

# Salvar chave privada em um arquivo
with open("chave_privada.txt", "wb") as file:
    file.write(key)

# Criar objeto Fernet com a chave pública
fernet = Fernet(key)

# Função para criptografar arquivo
def encrypt_file(file_name):
    with open(file_name, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_name, "wb") as file:
        file.write(encrypted_data)

# Função para descriptografar arquivo
def decrypt_file(file_name):
    with open(file_name, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open("decrypt_file.txt", "wb") as file:
        file.write(decrypted_data)

encrypt_file("example.txt")
decrypt_file("example.txt")
# decrypt_file("arquivo.txt")