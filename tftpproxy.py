import socket
from scapy.all import *

# Constants:

TFTP_PORT = 69 # TFTP works over UDP on its port 69
IP_PROXY = "192.168.40.80"
IP_SERVER = "192.168.30.90"
INTERFACE_NETWORK_PROXY = "enp0s3.30"
POS_OPCODE = 1 # According to RFC 1350, the OPCODE is on the second position (1 in array)
OPCODE_READING = 1
OPCODE_WRITING = 2
BUFFER_TFTP = 1024

# Functions:



server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((IP_PROXY, TFTP_PORT))
tftp_server_address = (IP_SERVER, TFTP_PORT)

# Infinite loop to receive and process messages:

while True:
	
	fw_proxy_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	fw_proxy_server.setsockopt(socket.SOL_SOCKET, 25, str(INTERFACE_NETWORK_PROXY + '\0').encode('utf-8'))
	fw_proxy_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	# Waiting for a packet:
	
	print(f"Waiting for rrq/wrq from client")
	request, client_address = server_socket.recvfrom(BUFFER_TFTP)

	request_mod = TFTP(request)
	request_mod_bytes = bytes(request_mod)

	if request[POS_OPCODE] == OPCODE_READING:
		fw_proxy_server.sendto(request_mod_bytes, tftp_server_address)
		print(f"Received RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
		print(f"Forwarding rrq to the Server: Server = {tftp_server_address}")

		tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		data_server_mod = TFTP(tftp_data_packet)
		data_server_mod_bytes = bytes(data_server_mod)

		fw_proxy_client.sendto(data_server_mod_bytes, client_address)
		print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
		print(f"Forwarding data to the Client: Client = {client_address}")

		ack_packet, client_address = fw_proxy_client.recvfrom(BUFFER_TFTP)

		ack_server_mod = TFTP(ack_packet)
		ack_server_mod_bytes = bytes(ack_server_mod)

		fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
		print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
		print(f"Forwarding ack to the Server: Server = {temp_server_address}")

	elif request[POS_OPCODE] == OPCODE_WRITING:

		fw_proxy_server.sendto(request_mod_bytes, tftp_server_address)
		
		print(f"Received WRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
		print(f"Forwarding wrq to the Server: Server = {tftp_server_address}")

		ack_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		ack_server_mod = TFTP(ack_packet)
		ack_server_mod_bytes = bytes(ack_server_mod)

		fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
		print(f"Received ACK from the Server: Server = {temp_server_address} | Data = {ack_server_mod_bytes}")
		print(f"Forwarding ack to the Client: Client = {client_address}")

		datapacket, clientaddress = fw_proxy_client.recvfrom(BUFFER_TFTP)

		datapacket_client_mod = TFTP(datapacket)
		datapacket_client_mod_bytes = bytes(datapacket_client_mod)

		fw_proxy_server.sendto(datapacket_client_mod_bytes, temp_server_address)
		print(f"Received Data-Packet from Client: Client = {clientaddress} | Data = {datapacket_client_mod_bytes}")
		print(f"Forwarding data to the Server: Server = {temp_server_address}")

		ack_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		ack_server_mod = TFTP(ack_packet)
		ack_server_mod_bytes = bytes(ack_server_mod)

		fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
		print(f"Received ACK from the Server: Server = {temp_server_address} | Data = {ack_server_mod_bytes}")
		print(f"Forwarding ack to the Client: Client = {client_address}")
