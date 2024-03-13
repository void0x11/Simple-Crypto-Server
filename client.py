import socket
import select
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class Client:
    '''
    A secure client class for sending encrypted messages to a server.

    This client uses RSA for asymmetric encryption of a symmetric key and Fernet
    for symmetric encryption of messages.
    '''

    COLORS = {
        'green': '\033[92m',
        'red': '\033[91m',
        'reset': '\033[0m'
    }

    def __init__(self):
        '''
        Initializes the client by setting up the connection and loading keys.
        '''
        self.public_key = self.load_public_key()
        self.symmetric_key = Fernet.generate_key()
        self.sock = self.setup_connection()

    def colored(self, text, color):
        '''
        Colors the text for terminal output.

        Args:
            text (str): The text to be colored.
            color (str): The color name ('green', 'red', 'reset').

        Returns:
            str: Colored text string.
        '''
        return self.COLORS.get(color, '') + text + self.COLORS['reset']

    def load_public_key(self):
        '''
        Loads the RSA public key from a file.

        Returns:
            The RSA public key.
        '''
        with open("public_key.pem", "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    def setup_connection(self):
        '''
        Establishes the socket connection.

        Returns:
            socket.socket: The configured socket object for communication.
        '''
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('localhost', 8443))
            print(self.colored("Connected to the server.", "green"))
            return sock
        except Exception as e:
            print(self.colored(f"Connection refused: {e}", "red"))
            exit(1)

    def is_connection_alive(self, sock):
        '''
        Checks if the connection to the server is still active.

        Args:
            sock (socket.socket): The client socket.

        Returns:
            bool: True if the connection is alive, False otherwise.
        '''
        ready_to_read, _, _ = select.select([sock], [], [], 0)
        if ready_to_read:
            try:
                # Check if data is available in the socket buffer
                if sock.recv(1, socket.MSG_PEEK):
                    return True
            except ConnectionError:
                return False
        return True

    def send_message(self, message):
        '''
        Encrypts and sends a message to the server.

        Args:
            message (str): The message to send.
        '''
        encrypted_message = Fernet(self.symmetric_key).encrypt(message.encode())
        try:
            self.sock.sendall(encrypted_message)
            print(self.colored("Message sent successfully.", "green"))
        except Exception as e:
            print(self.colored(f"Failed to send message: {e}", "red"))

    def run(self):
        '''
        The main loop for client operations. Handles message input and sending.
        '''
        encrypted_symmetric_key = self.public_key.encrypt(
            self.symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.sock.sendall(encrypted_symmetric_key)

        while True:
            if not self.is_connection_alive(self.sock):
                print(self.colored("Connection lost.", "red"))
                break
            message = input("Enter your message (or 'exit' to disconnect): ")
            if message.lower() == 'exit':
                break

            self.send_message(message)

        self.sock.close()
        print(self.colored("Disconnected from the server.", "green"))

if __name__ == "__main__":
    client = Client()
    client.run()
