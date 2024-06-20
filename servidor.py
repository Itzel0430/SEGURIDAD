import socket
import os
import hashlib
import subprocess

# Función para ocultar un mensaje en un archivo usando cat
def hide_message_in_file(encrypted_message_hex, file_path, output_file):

    with open(file_path, 'rb') as camuf:
            camuflaje = camuf.read()
    
    with open(encrypted_message_hex, 'rb') as inyeccion:
        encrypt_inyec = inyeccion.read()

        
    with open(os.path.join(rutaIncial ,output_file), 'wb') as new_file:
            new_file.write(camuflaje)
            new_file.write("--Hola--".encode())
            new_file.write(encrypt_inyec)

# Función para calcular el hash SHA-384 de un archivo
def calculate_sha384(file_path):
    sha384_hash = hashlib.sha384()
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            sha384_hash.update(data)
    return sha384_hash.hexdigest()

# Función para calcular el hash SHA-512 de un archivo
def calculate_sha512(file_path):
    sha512_hash = hashlib.sha512()
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            sha512_hash.update(data)
    return sha512_hash.hexdigest()

# Función para calcular el hash Blake2b de un archivo
def calculate_blake2b(file_path):
    blake2_hash = hashlib.blake2b()
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            blake2_hash.update(data)
    return blake2_hash.hexdigest()

# Configurar el socket del servidor
rutaIncial = "proyecto"
if not os.path.exists(rutaIncial):
    os.makedirs(rutaIncial)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 12345))
server_socket.listen(5)
print("Servidor esperando conexiones...")

while True:
    client_socket, client_address = server_socket.accept()
    print(f"Conexión establecida con: {client_address}")

    client_publickey_content = client_socket.recv(4096)
    with open(os.path.join(rutaIncial, 'client_publickey.pem'), 'wb') as pub_key_file:
        pub_key_file.write(client_publickey_content)
    print("Llave pública del cliente recibida y guardada.")

    print("Seleccione una opción:")
    print("1. Escribir un mensaje.")
    print("2. Seleccionar un archivo.")

    option = input("Ingrese el número de opción: ").strip()

    if option == '1':  # Opción para escribir un mensaje
        # Solicitar mensaje al usuario
        message = input("Ingrese el mensaje a enviar: ")

        try:
            mensajeTxt = os.path.join(rutaIncial, "mensaje_temp.txt")
            with open(mensajeTxt, 'w') as msg:
                msg.write(message)

            # Generar hash SHA-384 del mensaje original
            hash384_message = calculate_sha384(mensajeTxt)

            with open(os.path.join(rutaIncial, "hash1.txt"), 'w') as h384:
                h384.write(hash384_message)

            with open(os.path.join(rutaIncial, "hash1.txt"), 'rb') as envHah:
                dataH384 = envHah.read()
                client_socket.sendall(len(dataH384).to_bytes(4, 'big'))
                client_socket.sendall(dataH384)

            print(f"Hash SHA-384 del mensaje original: {hash384_message}")

            llave_pub = os.path.join(rutaIncial, 'client_publickey.pem')
            encriptado = os.path.join(rutaIncial, 'encrypt_file')

            subprocess.run(['openssl', 'pkeyutl', '-encrypt', '-inkey', llave_pub, '-pubin', '-in', mensajeTxt, '-out', encriptado])
            print('mensaje encriptado')

            # Calcular hash SHA-512 del mensaje encriptado
            hash_encrypt = calculate_sha512(encriptado)

            with open(os.path.join(rutaIncial, "hash2.txt"), 'w') as h512:
                h512.write(hash_encrypt)

            with open(os.path.join(rutaIncial, "hash2.txt"), 'rb') as envHah:
                dataH512 = envHah.read()
                client_socket.sendall(len(dataH512).to_bytes(4, 'big'))
                client_socket.sendall(dataH512)

            print(f"Hash SHA-512 del mensaje encriptado: {hash_encrypt}")

            file_path = input("Ingrese la ruta del archivo donde ocultar el mensaje: ")

            if not os.path.exists(file_path):
                raise RuntimeError(f"El archivo {file_path} no existe.")

            output_file = "output_with_message" + os.path.splitext(file_path)[1]

            hide_message_in_file(encriptado, file_path, output_file)

            # Calcular hash Blake2b del archivo oculto
            hash_stego = calculate_blake2b(output_file)

            with open(os.path.join(rutaIncial, "hash3.txt"), 'w') as hB2:
                hB2.write(hash_stego)

            with open(os.path.join(rutaIncial, "hash3.txt"), 'rb') as envHah:
                dataB2 = envHah.read()
                client_socket.sendall(len(dataB2).to_bytes(4, 'big'))
                client_socket.sendall(dataB2)

            print(f"Hash Blake2 del archivo oculto: {hash_stego}")

            os.remove(os.path.join(rutaIncial, "hash1.txt"))
            os.remove(os.path.join(rutaIncial, "hash2.txt"))
            os.remove(os.path.join(rutaIncial, "hash3.txt"))

            with open(output_file, 'rb') as file:
                while True:
                    chunk = file.read(4096)
                    if not chunk:
                        break
                    client_socket.sendall(chunk)
                    print("Se enviaron {} bytes".format(len(chunk)))

        except RuntimeError as e:
            print(f"Error al procesar el mensaje: {str(e)}")
    elif option == '2':  # Opción para seleccionar un archivo
        archivo = input("Ingrese la ruta del archivo a enviar: ")
        try:
            # Generar hash SHA-384 del mensaje original
            hash384_message = calculate_sha384(archivo)

            with open(os.path.join(rutaIncial, "hash1.txt"), 'w') as h384:
                h384.write(hash384_message)

            with open(os.path.join(rutaIncial, "hash1.txt"), 'rb') as envHah:
                dataH384 = envHah.read()
                client_socket.sendall(len(dataH384).to_bytes(4, 'big'))
                client_socket.sendall(dataH384)

            print(f"Hash SHA-384 del mensaje original: {hash384_message}")

            llave_pub = os.path.join(rutaIncial, 'client_publickey.pem')
            encriptado = os.path.join(rutaIncial, 'encrypt_file')

            subprocess.run(['openssl', 'pkeyutl', '-encrypt', '-inkey', llave_pub, '-pubin', '-in', mensajeTxt, '-out', encriptado])
            print('mensaje encriptado')

            # Calcular hash SHA-512 del mensaje encriptado
            hash_encrypt = calculate_sha512(encriptado)

            with open(os.path.join(rutaIncial, "hash2.txt"), 'w') as h512:
                h512.write(hash_encrypt)

            with open(os.path.join(rutaIncial, "hash2.txt"), 'rb') as envHah:
                dataH512 = envHah.read()
                client_socket.sendall(len(dataH512).to_bytes(4, 'big'))
                client_socket.sendall(dataH512)

            print(f"Hash SHA-512 del mensaje encriptado: {hash_encrypt}")

            file_path = input("Ingrese la ruta del archivo donde ocultar el mensaje: ")

            if not os.path.exists(file_path):
                raise RuntimeError(f"El archivo {file_path} no existe.")

            output_file = "output_with_message" + os.path.splitext(file_path)[1]

            hide_message_in_file(encriptado, file_path, output_file)

            # Calcular hash Blake2b del archivo oculto
            hash_stego = calculate_blake2b(output_file)

            with open(os.path.join(rutaIncial, "hash3.txt"), 'w') as hB2:
                hB2.write(hash_stego)

            with open(os.path.join(rutaIncial, "hash3.txt"), 'rb') as envHah:
                dataB2 = envHah.read()
                client_socket.sendall(len(dataB2).to_bytes(4, 'big'))
                client_socket.sendall(dataB2)

            print(f"Hash Blake2 del archivo oculto: {hash_stego}")

            os.remove(os.path.join(rutaIncial, "hash1.txt"))
            os.remove(os.path.join(rutaIncial, "hash2.txt"))
            os.remove(os.path.join(rutaIncial, "hash3.txt"))

            with open(output_file, 'rb') as file:
                while True:
                    chunk = file.read(4096)
                    if not chunk:
                        break
                    client_socket.sendall(chunk)
                    print("Se enviaron {} bytes".format(len(chunk)))

        except RuntimeError as e:
            print(f"Error al procesar el mensaje: {str(e)}")

    client_socket.close()

server_socket.close()