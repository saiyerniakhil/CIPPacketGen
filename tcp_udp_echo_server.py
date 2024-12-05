import socket
import threading

def tcp_echo_server(host='0.0.0.0', port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"TCP Echo Server listening on {host}:{port}")

        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_tcp_client, args=(client_socket, client_address)).start()

def handle_tcp_client(client_socket, client_address):
    with client_socket:
        print(f"TCP Connection from {client_address}")
        while True:
            data = client_socket.recv(1024)
            if not data:
                print(f"TCP Connection closed by {client_address}")
                break
            print(f"TCP Received from {client_address}: {data.decode()}")
            client_socket.sendall(data)

def udp_echo_server(host='0.0.0.0', port=12345):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))
        print(f"UDP Echo Server listening on {host}:{port}")

        while True:
            data, client_address = server_socket.recvfrom(1024)
            print(f"UDP Received from {client_address}: {data.decode()}")
            server_socket.sendto(data, client_address)

if __name__ == "__main__":
    # Start TCP server thread
    tcp_thread = threading.Thread(target=tcp_echo_server, args=('0.0.0.0', 12345), daemon=True)
    tcp_thread.start()

    # Start UDP server thread
    udp_thread = threading.Thread(target=udp_echo_server, args=('0.0.0.0', 12345), daemon=True)
    udp_thread.start()

    # Keep the main thread running
    tcp_thread.join()
    udp_thread.join()
