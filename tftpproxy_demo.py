import socket
from scapy.all import *
import time

# Constants:

TFTP_PORT = 69 # TFTP works over UDP on its port 69
IP_PROXY = "192.168.40.80"
IP_SERVER = "192.168.30.90"
INTERFACE_NETWORK_PROXY = "enp0s3.30"
POS_OPCODE = 1 # According to RFC 1350
OPCODE_READING = 1 # According to RFC 1350
OPCODE_WRITING = 2 # According to RFC 1350
OPCODE_DATA = 3 # According to RFC 1350
BUFFER_TFTP = 1024 # According to RFC 1350
MAX_TRANSFER_TFTP = 512 # According to RFC 1350

MIN_ATTACK_NUM = 0
MAX_ATTACK_NUM = 3
ATTACK_NO_ATTACK = 0
ATTACK_FILE_NOT_FOUND = 1
ATTACK_DROP_PACKET = 2
ATTACK_DROP_ACK = 3

FILE_NONEXISTENT = "nonexistent.txt"

# Functions:

def showInitialMenu():
	print("*** Welcome to tftpproxy ***")
	print("Please, choose one of the following attacks to be carried out:")
	print("")
	print("#\tError scenario\t\tExpected result")
	print("")
	print("0\tNo error\t\tNormal working")
	print("1\tFile not found (RRQ)\tReturn error code 1")
	print("2\tDrop client packet\tClient retransmits request")
	print("3\tDrop ACK client (RRQ)\tServer retransmits last byte")
	print("")

	chosenAttack = input("Chosen attack number: ")

	return chosenAttack

def chooseAttack():
	chosenAttackError = True
	while chosenAttackError:
		chosenAttack = showInitialMenu()

		try:
			chosenAttack = int(chosenAttack)
			if chosenAttack in range(MIN_ATTACK_NUM, MAX_ATTACK_NUM + 1):
				chosenAttackError = False
		except ValueError:
			print("Please, introduce a valid number")

	return chosenAttack

def applyModRequest(packet, chosenAttack, mode):
	if chosenAttack == ATTACK_FILE_NOT_FOUND:
		packet.filename = FILE_NONEXISTENT
		print(f"altered filename = {packet.filename}")

	return packet

def getBytesForPacket(packet):
	size = len(packet.load)
	return size

def packetHasLoad(packet):
	packet_str = packet.show(dump=True)
	return "load" in packet_str

def readingLogic(chosenAttack, data_server_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address):

	data_server_mod_bytes = bytes(data_server_mod)

	if not (chosenAttack == ATTACK_DROP_PACKET):
		fw_proxy_client.sendto(data_server_mod_bytes, client_address)
		print(f"Received data from Server: Server = {server_address} | Data = {data_server_mod_bytes}")
		print(f"Forwarding data to the Client: Client = {client_address}")
	else:
		print(f"Received data from Server: Server = {server_address} | Data = {data_server_mod_bytes}")
		print(f"Omitting forwarding from server to client")
		print(f"Waiting for re-sending from client")
		request, client_address = server_socket.recvfrom(BUFFER_TFTP)
		request_mod = TFTP(request)

		request_mod_bytes = bytes(request_mod)

		fw_proxy_server.sendto(request_mod_bytes, server_address)
		print(f"Received RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
		print(f"Forwarding rrq to the Server: Server = {server_address}")

		tftp_data_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		data_server_mod = TFTP(tftp_data_packet)
		data_server_mod_bytes = bytes(data_server_mod)

		fw_proxy_client.sendto(data_server_mod_bytes, client_address)
		print(f"Received data from Server: Server = {server_address} | Data = {data_server_mod_bytes}")
		print(f"Forwarding data to the Client: Client = {client_address}")
	
	if not (chosenAttack == ATTACK_FILE_NOT_FOUND):
		ack_packet, client_address = fw_proxy_client.recvfrom(BUFFER_TFTP)
		ack_server_mod = TFTP(ack_packet)
		ack_server_mod_bytes = bytes(ack_server_mod)

		if not (chosenAttack == ATTACK_DROP_ACK):
			fw_proxy_server.sendto(ack_server_mod_bytes, server_address)
			print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
			print(f"Forwarding ack to the Server: Server = {server_address}")

		elif chosenAttack == ATTACK_DROP_ACK:
			print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
			print(f"Omitting forwarding from client to server")
			print(f"Waiting for re-sending from server")
			tftp_data_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

			data_server_mod = TFTP(tftp_data_packet)
			data_server_mod_bytes = bytes(data_server_mod)

			fw_proxy_client.sendto(data_server_mod_bytes, client_address)
			print(f"Received data from Server: Server = {server_address} | Data = {data_server_mod_bytes}")
			print(f"Forwarding data to the Client: Client = {client_address}")

			ack_server_mod = TFTP(ack_packet)
			ack_server_mod_bytes = bytes(ack_server_mod)

			fw_proxy_server.sendto(ack_server_mod_bytes, server_address)
			print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
			print(f"Forwarding ack to the Server: Server = {server_address}")



def writingLogic(chosenAttack, datapacket_client_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address):
	
	datapacket_client_mod_bytes = bytes(datapacket_client_mod)

	fw_proxy_server.sendto(datapacket_client_mod_bytes, server_address)
	print(f"Received Data-Packet from Client: Client = {clientaddress} | Data = {datapacket_client_mod_bytes}")
	print(f"Forwarding data to the Server: Server = {server_address}")

	ack_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

	ack_server_mod = TFTP(ack_packet)
	ack_server_mod_bytes = bytes(ack_server_mod)

	fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
	print(f"Received ACK from the Server: Server = {server_address} | Data = {ack_server_mod_bytes}")
	print(f"Forwarding ack to the Client: Client = {client_address}")


# Entry point:

chosenAttack = chooseAttack()
oldChosenAttack = chosenAttack

# Infinite loop to receive and process messages:

while True:

	chosenAttack = oldChosenAttack

	server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_socket.bind((IP_PROXY, TFTP_PORT))
	server_address = (IP_SERVER, TFTP_PORT)

	fw_proxy_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	fw_proxy_server.setsockopt(socket.SOL_SOCKET, 25, str(INTERFACE_NETWORK_PROXY + '\0').encode('utf-8'))
	fw_proxy_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	lastPacketOfChain = False

	print(f"Waiting for rrq/wrq from client")
	request, client_address = server_socket.recvfrom(BUFFER_TFTP)

	request_mod = TFTP(request)

	mode = request_mod.op

	if chosenAttack == ATTACK_FILE_NOT_FOUND:
		request_mod = applyModRequest(request_mod, chosenAttack, mode)

	request_mod_bytes = bytes(request_mod)

	mode = request_mod.op

	if mode == OPCODE_READING:
		fw_proxy_server.sendto(request_mod_bytes, server_address)
		print(f"Received RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
		print(f"Forwarding rrq to the Server: Server = {server_address}")

		tftp_data_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		data_server_mod = TFTP(tftp_data_packet)
		size = 0

		if chosenAttack == ATTACK_FILE_NOT_FOUND:
			size = SIZE_ERROR_PACK
		else:
			if packetHasLoad(data_server_mod):
				size = getBytesForPacket(data_server_mod)
			else:
				size = MAX_TRANSFER_TFTP

		while size >= MAX_TRANSFER_TFTP:

			readingLogic(chosenAttack, data_server_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address)

			tftp_data_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)
			tftp_data_packet = TFTP(tftp_data_packet)

			if packetHasLoad(tftp_data_packet):
				size = getBytesForPacket(tftp_data_packet)
				lastPacketOfChain = True
			else:
				size = 0
				lastPacketOfChain = True

			chosenAttack = ATTACK_NO_ATTACK

		if size < MAX_TRANSFER_TFTP:

			if lastPacketOfChain == True:
				data_server_mod = tftp_data_packet

			readingLogic(chosenAttack, data_server_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address)


	elif mode == OPCODE_WRITING:

		print(f"Received WRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")

		if not (chosenAttack == ATTACK_DROP_PACKET):
			fw_proxy_server.sendto(request_mod_bytes, server_address)
			print(f"Forwarding wrq to the Server: Server = {server_address}")
		else:
			print(f"Omitting forwarding to the Server")
			print(f"Waiting for re-sending from client")
			request, client_address = server_socket.recvfrom(BUFFER_TFTP)
			request_mod = TFTP(request)
			request_mod_bytes = bytes(request_mod)
			print(f"Received WRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
			fw_proxy_server.sendto(request_mod_bytes, server_address)
			print(f"Forwarding wrq to the Server: Server = {server_address}")

		ack_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		ack_server_mod = TFTP(ack_packet)
		ack_server_mod_bytes = bytes(ack_server_mod)

		print(f"Received ACK/error from the Server: Server = {server_address} | Data = {ack_server_mod_bytes}")

		fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
		print(f"Forwarding ack/error to the Client: Client = {client_address}")

		if not (chosenAttack == ATTACK_FILE_NOT_FOUND):

			datapacket, clientaddress = fw_proxy_client.recvfrom(BUFFER_TFTP)

			datapacket_client_mod = TFTP(datapacket)

			if chosenAttack == ATTACK_FILE_NOT_FOUND:
				size = SIZE_ERROR_PACK
			else:
				if packetHasLoad(datapacket_client_mod):
					size = getBytesForPacket(datapacket_client_mod)
				else:
					size = MAX_TRANSFER_TFTP

			while size >= MAX_TRANSFER_TFTP:

				writingLogic(chosenAttack, datapacket_client_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address)

				datapacket, clientaddress = fw_proxy_client.recvfrom(BUFFER_TFTP)
				datapacket_client_mod = TFTP(datapacket)

				if packetHasLoad(datapacket_client_mod):
					size = getBytesForPacket(datapacket_client_mod)
					lastPacketOfChain = True
				else:
					size = 0
					lastPacketOfChain = True

				chosenAttack = ATTACK_NO_ATTACK

			if size < MAX_TRANSFER_TFTP:

				if lastPacketOfChain == True:
					datapacket_client_mod = datapacket

				writingLogic(chosenAttack, datapacket_client_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address)

	else:
		print(f"Unknown op code. Descarting packet...")

	fw_proxy_client.close()
	fw_proxy_server.close()
	server_socket.close()
