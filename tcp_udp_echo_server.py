import socket
import threading

# TCP Echo Server
def tcp_echo_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse the address
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"TCP Echo Server listening on {host}:{port}")

    def handle_client(client_socket, client_address):
        print(f"TCP connection established with {client_address}")
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                client_socket.sendall(data)  # Echo back the data
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            print(f"TCP connection with {client_address} closed")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True  # Daemon threads close when the main thread exits
            ).start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server_socket.close()
        print("Server socket closed")

# UDP Echo Server
def udp_echo_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"UDP Echo Server listening on {host}:{port}")

    while True:
        data, client_address = server_socket.recvfrom(1024)
        print(f"UDP message from {client_address}")
        server_socket.sendto(data, client_address)  # Echo back the data


if __name__ == "__main__":
    host = "10.0.0.46"
    tcp_port = 12345
    udp_port = 2222

    # Start TCP Echo Server in a thread
    threading.Thread(target=tcp_echo_server, args=(host, tcp_port)).start()

    # Start UDP Echo Server in a thread
    threading.Thread(target=udp_echo_server, args=(host, udp_port)).start()
