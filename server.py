import socket
import os
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

class Server:
    '''
    A server class that handles secure connections and message decryption.

    The server uses RSA for asymmetric decryption of a symmetric key and Fernet for
    symmetric decryption of messages.
    '''

    COLORS = {
        'green': '\033[92m',
        'yellow': '\033[93m',
        'red': '\033[91m',
        'reset': '\033[0m'
    }

    def __init__(self, host='localhost', port=8443):
        '''
        Initializes the server with the given host and port.

        Args:
            host (str): The hostname to bind the server to.
            port (int): The port number to bind the server to.
        '''
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.private_key = self.load_or_generate_keys()

    def colored(self, text, color):
        '''
        Returns colored text for the terminal output.

        Args:
            text (str): The text to color.
            color (str): The color name ('green', 'yellow', 'red', 'reset').

        Returns:
            str: Colored text string.
        '''
        return self.COLORS.get(color, '') + text + self.COLORS['reset']

    def generate_private_key(self, keyfile_path):
        '''
        Generates an RSA private key.

        Args:
            keyfile_path (str): Path to save the generated private key.

        Returns:
            rsa.RSAPrivateKey: The generated RSA private key.
        '''
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open(keyfile_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return private_key

    def generate_public_key(self, private_key, public_key_path):
        '''
        Generates an RSA public key based on the provided private key.

        Args:
            private_key (rsa.RSAPrivateKey): The private key to generate the public key from.
            public_key_path (str): Path to save the generated public key.
        '''
        public_key = private_key.public_key()
        with open(public_key_path, "wb") as key_file:
            key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_or_generate_keys(self):
        '''
        Loads or generates RSA key pair (private and public keys).

        Returns:
            rsa.RSAPrivateKey: The loaded or generated RSA private key.
        '''
        keyfile_path = "private_key.pem"
        public_key_path = "public_key.pem"

        if not os.path.exists(keyfile_path) or not os.path.exists(public_key_path):
            print(self.colored("Key pair not found, generating new ones...", "yellow"))
            private_key = self.generate_private_key(keyfile_path)
            self.generate_public_key(private_key, public_key_path)
            print(self.colored("Key pair generated.", "green"))
        else:
            with open(keyfile_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            print(self.colored("Key pair loaded.", "green"))

        return private_key

    def decrypt_symmetric_key(self, encrypted_key):
        '''
        Decrypts the symmetric key received from the client.

        Args:
            encrypted_key (bytes): The encrypted symmetric key.

        Returns:
            bytes: The decrypted symmetric key.
        '''
        try:
            print(self.colored(f"Length of encrypted symmetric key received: {len(encrypted_key)}", "yellow"))
            return self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(self.colored(f"Failed to decrypt symmetric key: {e}", "red"))
            raise

    def cleanup_key_files(self):
        '''
        Removes the RSA key files from the file system.
        '''
        os.remove("private_key.pem")
        os.remove("public_key.pem")
        print(self.colored("Key files removed.", "red"))

    def start(self):
        '''
        Starts the server to listen for incoming client connections and handle them.
        '''
        self.sock.listen(5)
        print(self.colored(f"Server started, waiting for client connections on {self.host}:{self.port}...", "yellow"))

        while True:
            try:
                # Accept incoming client connections
                connection, client_address = self.sock.accept()
                print(self.colored(f"Connected to {client_address}", "green"))

                # Receive the encrypted symmetric key from the client
                encrypted_symmetric_key = connection.recv(self.private_key.key_size)
                if not encrypted_symmetric_key:
                    print(self.colored("No symmetric key received. Closing connection.", "red"))
                    connection.close()
                    continue

                # Decrypt the symmetric key
                symmetric_key = self.decrypt_symmetric_key(encrypted_symmetric_key)
                fernet = Fernet(symmetric_key)

                while True:
                    # Receive and decrypt messages from the client
                    encrypted_message = connection.recv(4096)
                    if not encrypted_message:
                        print(self.colored("Client disconnected. Waiting for new connections...", "yellow"))
                        break

                    decrypted_message = fernet.decrypt(encrypted_message)
                    print(self.colored(f"Decrypted message: {decrypted_message.decode()}", "green"))

                    # Save the received message to a file
                    with open("received_message.txt", "a+", encoding="utf-8") as file:
                        file.write(decrypted_message.decode() + '\n')
                    print(self.colored("Message saved to 'received_message.txt'.", "green"))

                # Close the client connection and generate new keys for the next client
                connection.close()
                # Generate new keys for the next client
                self.private_key = self.load_or_generate_keys()

            except Exception as e:
                print(self.colored(f"An error occurred: {e}", "red"))
                if connection:
                    connection.close()

        # Cleanup: Remove key files
        self.cleanup_key_files()

if __name__ == "__main__":
    server = Server()
    server.start()
