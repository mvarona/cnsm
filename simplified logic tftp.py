import socket
from scapy.all import *
import time

def getBytesForPacket(packet):
	size = len(packet.load)
	return size

def packetHasLoad(packet):
	packet_str = packet.show(dump=True)
	return "load" in packet_str

def readingLogic(chosenAttack, data_server_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address):

	data_server_mod_bytes = bytes(data_server_mod)

	fw_proxy_client.sendto(data_server_mod_bytes, client_address)
	print(f"\nReceived data from Server: Server = {server_address} | Data = {data_server_mod_bytes}")
	print(f"Forwarding data to the Client: Client = {client_address}\n")

	request, client_address = server_socket.recvfrom(BUFFER_TFTP)
	request_mod = TFTP(request)

	request_mod_bytes = bytes(request_mod)

	fw_proxy_server.sendto(request_mod_bytes, server_address)
	print(f"\nReceived RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
	print(f"Forwarding rrq to the Server: Server = {server_address}\n")

	tftp_data_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

	data_server_mod = TFTP(tftp_data_packet)
	data_server_mod_bytes = bytes(data_server_mod)

	fw_proxy_client.sendto(data_server_mod_bytes, client_address)
	print(f"\nReceived data from Server: Server = {server_address} | Data = {data_server_mod_bytes}")
	print(f"Forwarding data to the Client: Client = {client_address}\n")
	
	ack_packet, client_address = fw_proxy_client.recvfrom(BUFFER_TFTP)
	ack_server_mod = TFTP(ack_packet)
	ack_server_mod_bytes = bytes(ack_server_mod)

	fw_proxy_server.sendto(ack_server_mod_bytes, server_address)
	print(f"\nReceived ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
	print(f"Forwarding ack to the Server: Server = {server_address}\n")


while True:
	...
	print(f"Waiting for rrq/wrq from client\n")
	request, client_address = server_socket.recvfrom(1024)
	request_mod = TFTP(request)

	if request_mod.op == 1:

		fw_proxy_server.sendto(request_mod_bytes, server_address)
		print(f"\nReceived RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
		print(f"Forwarding rrq to the Server: Server = {server_address}\n")

		tftp_data_packet, server_address = fw_proxy_server.recvfrom(1024)

		data_server_mod = TFTP(tftp_data_packet)
		size = 0

		if packetHasLoad(data_server_mod):
				size = getBytesForPacket(data_server_mod)
		else:
			size = 512

		while size >= 512:

			#reading logic would be here

			data_server, server_address = fw_proxy_server.recvfrom(1024)
			data_server_mod = TFTP(data_server)

			if packetHasLoad(data_server_mod):
				size = getBytesForPacket(data_server_mod)
			else:
				size = 0

		if size < 512:

			#reading logic would be here

	fw_proxy_client.close()
	fw_proxy_server.close()
	server_socket.close()