import socket
import os
import hashlib
import subprocess

# Función para generar el HASH Blake2 del archivo
def generate_blake2_hash(data):
    blake2_hash = hashlib.blake2b(data).hexdigest()
    return blake2_hash

def generate_sha512_hash(data):
    sha512_hash = hashlib.sha512(data).hexdigest()
    return sha512_hash


# Función para verificar el HASH Blake2 del archivo
def verify_blake2_hash(file_path, expected_hash):
    print(file_path)
    try:
        with open(file_path, 'r') as file:
            file_data = file.read()

        return file_data == expected_hash
    except Exception as e:
        print('Error de lectura')
        return False

# Función para extraer el mensaje oculto del archivo
def extract_hidden_message(file_path):
    # Suponiendo que el mensaje está oculto al final del archivo usando 'cat'
    with open(file_path, 'r') as file:
        lines = file.readlines()
        # Última línea debería contener el mensaje oculto
        hidden_message = lines[-1].strip()  # Elimina cualquier espacio adicional
        return hidden_message

def extract_files_from_combined_file(combined_file_path, carpeta_proyecto):
    delimiter="--Hola--"

    with open(combined_file_path, 'rb') as combined_file:
        combined_data = combined_file.read()

    delimiter_index = combined_data.find(delimiter.encode())
    
    if delimiter_index == -1:
        raise ValueError("Delimiter not found in the combined file")

    camuflaje = combined_data[:delimiter_index]
    encrypt_inyec = combined_data[delimiter_index + len(delimiter):]

    ruta_camuflaje = os.path.join(carpeta_proyecto, "camuflaje")
    ruta_encriptado = os.path.join(carpeta_proyecto, "encriptado")
    
    with open(ruta_camuflaje, 'wb') as camuf_file:
        camuf_file.write(camuflaje)

    with open(ruta_encriptado, 'wb') as inject_file:
        inject_file.write(encrypt_inyec)

# Solicitar la IP del servidor
server_ip = input("Ingrese la IP del servidor: ")

# Configurar el socket del cliente
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, 12345))

# Enviar la llave pública al servidor (ejemplo)
carpeta_proyecto = 'proyecto'
if not os.path.exists(carpeta_proyecto):
    os.makedirs(carpeta_proyecto)

#Llave privada
llave_priv_ruta = os.path.join(carpeta_proyecto, "llavePriv")

subprocess.run(['openssl', 'genrsa', '-out', llave_priv_ruta], check=True)

llave_pub_ruta = os.path.join(carpeta_proyecto, "llavepublica.pem")

subprocess.run(['openssl', 'rsa', '-in', llave_priv_ruta, '-outform', 'PEM', '-pubout', '-out', llave_pub_ruta])

with open(llave_pub_ruta, 'rb') as file:
    llave_publica = file.read()
client_socket.sendall(llave_publica)

try:
    # Recibir el tamaño del hash
    hashrecive = client_socket.recv(4)
    if not hashrecive:
        raise ValueError("No se recibieron datos para el tamaño del hash")
    hashsize = int.from_bytes(hashrecive, "big")
    print(f"Tamaño del hash recibido: {hashsize}")

    # Recibir el hash
    dataSize = client_socket.recv(hashsize)
    if not dataSize:
        raise ValueError("No se recibieron datos para el hash")
    print(f"Hash recibido: {dataSize.decode()}")

    with open(os.path.join(carpeta_proyecto, 'hash384.txt'), 'wb') as hash384:
        hash384.write(dataSize)
    
        # Recibir el tamaño del hash
    hashrecive = client_socket.recv(4)
    if not hashrecive:
        raise ValueError("No se recibieron datos para el tamaño del hash")
    hashsize = int.from_bytes(hashrecive, "big")
    print(f"Tamaño del hash recibido: {hashsize}")

    # Recibir el hash
    dataSize = client_socket.recv(hashsize)
    if not dataSize:
        raise ValueError("No se recibieron datos para el hash")
    print(f"Hash recibido: {dataSize.decode()}")

    with open(os.path.join(carpeta_proyecto, 'hash512.txt'), 'wb') as hash512:
        hash512.write(dataSize)

            # Recibir el tamaño del hash
    hashrecive = client_socket.recv(4)
    if not hashrecive:
        raise ValueError("No se recibieron datos para el tamaño del hash")
    hashsize = int.from_bytes(hashrecive, "big")
    print(f"Tamaño del hash recibido: {hashsize}")

    # Recibir el hash
    dataSize = client_socket.recv(hashsize)
    if not dataSize:
        raise ValueError("No se recibieron datos para el hash")
    print(f"Hash recibido: {dataSize.decode()}")

    with open(os.path.join(carpeta_proyecto, 'Blake2.txt'), 'wb') as hash512:
        hash512.write(dataSize)

    
except Exception as e:
    print('Error al recibir el hash:', e)


"""
with open(os.path.join(carpeta_proyecto, 'hash512.txt'), 'w') as hash512:
    hash512.write(hash_sha512_received)

with open(os.path.join(carpeta_proyecto, 'Blake2.txt'), 'w') as hashB2:
    hashB2.write(hash_blake2_received)
"""
    

    # Recibir y guardar el archivo resultante
output_file_path = os.path.join(carpeta_proyecto, 'stego')
try:

        # Abrir el archivo para escritura en modo binario ('wb')
        with open(output_file_path, 'wb') as f:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                f.write(data)
                print("Se recibieron {} bytes".format(len(data)))

        print(f"Archivo recibido y guardado como: {output_file_path}")
except Exception as e:
        print('Error:', e)

with open(os.path.join(carpeta_proyecto, 'Blake2.txt'), 'r') as hashB2:
    hash_blake2 = hashB2.read()

# Verificar el hash Blake2 del archivo 'stego'
with open(os.path.join(carpeta_proyecto, 'Blake2.txt'), 'r') as hashB2:
    hash_blake2_expected = hashB2.read().strip()

# Leer el archivo 'stego' y generar su hash Blake2
try:
    with open(output_file_path, 'rb') as stego_file:
        stego_data = stego_file.read()
        hash_blake2_generated = generate_blake2_hash(stego_data)

    # Comparar el hash generado con el esperado
    if hash_blake2_generated == hash_blake2_expected:
        extract_files_from_combined_file(output_file_path, carpeta_proyecto)
        os.remove(output_file_path)
        os.remove(os.path.join(carpeta_proyecto, "camuflaje"))
        print("El hash Blake2 del archivo 'stego' es correcto.")

        with open(os.path.join(carpeta_proyecto, 'hash512.txt'), 'r') as hash512sum:
            hash_sha512_expected = hash512sum.read().strip()
        
        with open(os.path.join(carpeta_proyecto, "encriptado"), 'rb') as encrypt_file:
            encriptado_data = encrypt_file.read()
            hash_512sum_generated = generate_sha512_hash(encriptado_data)
        
            # Debugging prints
        print(f"Hash SHA-512 esperado: {hash_sha512_expected}")
        print(f"Hash SHA-512 generado: {hash_512sum_generated}")
        
        if hash_512sum_generated == hash_sha512_expected:
            encriptado_file = os.path.join(carpeta_proyecto, "encriptado")
            desencriptado_file = os.path.join(carpeta_proyecto, "archivo_desencriptado")
            subprocess.run( ['openssl', 'pkeyutl', '-decrypt','-inkey', llave_priv_ruta,'-in', encriptado_file, '-out', desencriptado_file], check=True)
            print("El hash sha512 del archivo encriptado es correcto.")
        else:
            #os.remove(os.path.join(carpeta_proyecto, "encriptado"))
            print("El hash sha512 del archivo encriptado es correcto, el archivo se removio.")

    else:
        os.remove(output_file_path)
        print("El hash Blake2 del archivo 'stego' no coincide.")

except Exception as e:
    print(f'Error al generar/verificar el hash Blake2: {e}')