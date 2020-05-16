import socket
from scapy.all import *

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("192.168.40.80", 69))
tftp_server_address = ("192.168.30.90", 69)

while True:
	fw_proxy_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	fw_proxy_server.setsockopt(socket.SOL_SOCKET, 25, str("enp0s3.30" + '\0').encode('utf-8'))
	fw_proxy_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	#Waiting for a packet
	print(f"Waiting for rrq/wrq from client")
	request, client_address = server_socket.recvfrom(1024)
	if request[1] == 1:
		fw_proxy_server.sendto(request, tftp_server_address)
		print(f"Received RRQ from the Client: Client = {client_address} | Request = {request}")
		print(f"Forwarding rrq to the Server: Server = {tftp_server_address}")

		tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(1024)

		tftp_data_packet = TFTP(tftp_data_packet)

		size = len(tftp_data_packet.load)
		print(size)

		while size >= 512:

			tftp_data_packet = bytes(tftp_data_packet)


			fw_proxy_client.sendto(tftp_data_packet, client_address)
			print(f"Received data from Server: Server = {temp_server_address} | Data = {tftp_data_packet}")
			print(f"Forwarding data to the Client: Client = {client_address}")

			ack_packet, client_address = fw_proxy_client.recvfrom(1024)
			fw_proxy_server.sendto(ack_packet, temp_server_address)
			print(f"Received ACK from the Client: Client = {client_address} | ACK-Data = {ack_packet}")
			print(f"Forwarding ack to the Server: Server = {temp_server_address}")

			tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(1024)

			tftp_data_packet = TFTP(tftp_data_packet)
			print("LOOK HERE")
			print(tftp_data_packet.load)
			print(tftp_data_packet.load is None)

			size = len(tftp_data_packet.load)
			print(size)

		if size < 512:
			
			tftp_data_packet = bytes(tftp_data_packet)


			fw_proxy_client.sendto(tftp_data_packet, client_address)
			print(f"Received data from Server: Server = {temp_server_address} | Data = {tftp_data_packet}")
			print(f"Forwarding data to the Client: Client = {client_address}")

			ack_packet, client_address = fw_proxy_client.recvfrom(1024)
			fw_proxy_server.sendto(ack_packet, temp_server_address)
			print(f"Received ACK from the Client: Client = {client_address} | ACK-Data = {ack_packet}")
			print(f"Forwarding ack to the Server: Server = {temp_server_address}")

	elif request[1] == 2:
		fw_proxy_server.sendto(request, tftp_server_address)
		print(f"Received WRQ from the Client: Client = {client_address} | Request = {request}")
		print(f"Forwarding wrq to the Server: Server = {tftp_server_address}")

		ack_packet, temp_server_address = fw_proxy_server.recvfrom(1024)
		fw_proxy_client.sendto(ack_packet, client_address)
		print(f"Received ACK from the Server: Server = {temp_server_address} | ACK-Data = {ack_packet}")
		print(f"Forwarding ack to the Client: Client = {client_address}")

		datapacket, clientaddress = fw_proxy_client.recvfrom(1024)
		fw_proxy_server.sendto(datapacket, temp_server_address)
		print(f"Received Data-Packet from Client: Client = {clientaddress} | Data = {datapacket}")
		print(f"Forwarding data to the Server: Server = {temp_server_address}")

		ack_packet, temp_server_address = fw_proxy_server.recvfrom(1024)
		fw_proxy_client.sendto(ack_packet, client_address)
		print(f"Received ACK from the Server: Server = {temp_server_address} | ACK-Data = {ack_packet}")
		print(f"Forwarding ack to the Client: Client = {client_address}")
