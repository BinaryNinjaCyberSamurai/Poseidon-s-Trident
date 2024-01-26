# client.py
import socket
import ssl
import configparser

def load_config():
    config = configparser.ConfigParser()
    config.read('client_config.ini')  # Replace with the path to your configuration file
    return config

def start_client():
    config = load_config()

    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the server's address and port
    server_address = (config['Server']['host'], int(config['Server']['port']))
    client_socket.connect(server_address)

    # Wrap the socket with SSL/TLS
    ssl_socket = ssl.wrap_socket(
        client_socket,
        cert_reqs=ssl.CERT_NONE,
        keyfile=config['SSL']['key_file'],
        certfile=config['SSL']['cert_file']
    )

    try:
        # Send data
        message = "Hello, server! This is a secure client."
        ssl_socket.sendall(message.encode('utf-8'))
        print(f"Sent: {message}")

        # Receive the response
        data = ssl_socket.recv(1024)
        print(f"Received: {data.decode('utf-8')}")

    finally:
        # Close the connection
        ssl_socket.close()

if __name__ == "__main__":
    start_client()
