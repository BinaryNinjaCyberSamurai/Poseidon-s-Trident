# server.py
import socket
import ssl
import configparser

def load_config():
    config = configparser.ConfigParser()
    config.read('server_config.ini')  # Replace with the path to your configuration file
    return config

def start_server():
    config = load_config()

    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a specific address and port
    server_address = (config['Server']['host'], int(config['Server']['port']))
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(1)

    print(f"Server listening on {server_address}")

    while True:
        try:
            # Wait for a connection
            print("Waiting for a connection...")
            connection, client_address = server_socket.accept()

            # Wrap the socket with SSL/TLS
            ssl_connection = ssl.wrap_socket(
                connection,
                keyfile=config['SSL']['key_file'],
                certfile=config['SSL']['cert_file'],
                server_side=True
            )

            try:
                print(f"Accepted connection from {client_address}")

                # Receive and send data over the secure connection
                data = ssl_connection.recv(1024)
                print(f"Received: {data.decode('utf-8')}")

                ssl_connection.sendall("Hello, client! This is a secure server.".encode('utf-8'))

            finally:
                # Close the connection
                ssl_connection.close()

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    start_server()
