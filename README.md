# Secure Messaging Server and Client

This project consists of a secure messaging server and client that demonstrate secure communication practices using Python. The server and client use asymmetric and symmetric encryption to ensure confidentiality and integrity of messages.

## Server

The server is responsible for receiving incoming connections from clients, managing encryption keys, and storing received messages.

### Server Features:

- **Secure Key Management**: The server generates and loads RSA key pairs for secure communication. Keys are securely stored in `"private_key.pem"` and `"public_key.pem"` files.

- **Encryption**: Communication between the server and clients is encrypted using a combination of RSA for key exchange and Fernet (AES encryption) for message encryption.

- **Persistent Message Storage**: The server saves received messages to a file `"received_message.txt"`.

- **Graceful Handling of Disconnections**: The server handles client disconnections gracefully, generates new encryption keys for the next client, and continues listening for new connections.

### To Run the Server:

1. Run the server script:
```
python server.py
```
2. The server will listen for incoming connections on the specified host and port (default: `localhost:8443`).

3. Clients can connect to the server to send and receive secure messages.

## Client

The client allows users to send messages securely to the server. It generates a symmetric key, encrypts messages, and sends them to the server.

### Client Features:

- **Secure Key Management**: The client generates a symmetric key and encrypts it with the server's public key before sending it for secure key exchange.

- **Message Encryption**: Messages are encrypted using the symmetric key (Fernet encryption) before transmission.

- **Graceful Handling of Disconnections**: The client checks for connection status and gracefully handles disconnections.

### To Run the Client:

1. Run the client script:
```
python client.py
```
2. The client will establish a connection to the server at `localhost:8443`.

3. Enter messages to send securely to the server. Type `'exit'` to disconnect from the server.

## Improvements

While this project demonstrates secure communication practices, there are opportunities for further improvement:

- **Enhanced Key Storage**: Consider storing private keys securely, possibly using hardware security modules (HSMs) or encrypted key storage.

- **Improved Error Handling**: Implement more robust error handling, especially around cryptographic operations, to avoid revealing sensitive information in error messages.

- **Use of Established Protocols**: For production use, consider implementing communication using established protocols like TLS for secure end-to-end encryption and authentication.

- **Configuration Flexibility**: Make host and port configurable via environment variables or configuration files to allow for more flexible deployments.

- **Key Rotation**: Implement key rotation strategies to regularly update encryption keys for better security.

- **Multithreaded Server**: Consider using Object-Oriented Programming (OOP) principles to create a multithreaded server that can handle multiple client connections simultaneously, making it suitable for building online messaging applications.

