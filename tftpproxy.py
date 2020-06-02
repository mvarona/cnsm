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
VALUES_IN_LAST_PACKET_TFTP = 1 # According to RFC 1350

MIN_ATTACK_NUM = 0
MAX_ATTACK_NUM = 10
ATTACK_NO_ATTACK = 0
ATTACK_FILE_NOT_FOUND = 1
ATTACK_ACCESS_VIOLATION = 2
ATTACK_ILLEGAL_OP = 3
ATTACK_CHANGE_ACK = 4
ATTACK_FILE_NOT_FOUND_WRQ = 5
ATTACK_DROP_PACKET = 6
ATTACK_DROP_ACK = 7
ATTACK_CHANGE_BLOCK = 8
ATTACK_TWICE_ACK = 9
ATTACK_CHANGE_TXT = 10

FILE_NONEXISTENT = "nonexistent.txt"
FILE_FORBIDDEN = "forbidden.txt"
TEXT_CHANGED = "!!!THIS TEXT WAS ALTERED!!!\n"
SIZE_ERROR_PACK = 10
OP_ILLEGAL = 8

# Functions:

def showInitialMenu():
	print("*** Welcome to tftpproxy ***")
	print("Please, choose one of the following attacks to be carried out:")
	print("")
	print("#\tError scenario\t\tExpected result")
	print("")
	print("0\tNo error\t\tNormal working")
	print("1\tFile not found (RRQ)\tReturn error code 1")
	print("2\tAccess violation (WRQ)\tReturn error code 2")
	print("3\tIllegal TFTP op.\tServer discards request")
	print("4\tChange ACK number\tOther part retransmits data")
	print("5\tFile not found (WRQ)\tReturn error code 1")
	print("6\tDrop server packet\tClient retransmits request")
	print("7\tDrop ACK client (RRQ)\tServer retransmits last block")
	print("8\tChange block num. (RRQ)\tClient retransmits request")
	print("9\tSend ACK twice\t\tSecond ACK is ignored")
	print("10\tModify file text\tOther part accepts text")
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

	if (chosenAttack == ATTACK_FILE_NOT_FOUND and mode == OPCODE_READING) or (chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ and mode == OPCODE_WRITING):
		packet.filename = FILE_NONEXISTENT
		print(f"altered filename = {packet.filename}")

	if chosenAttack == ATTACK_ACCESS_VIOLATION:
		packet.filename = FILE_FORBIDDEN
		print(f"altered filename = {packet.filename}")

	if chosenAttack == ATTACK_ILLEGAL_OP:
		packet.op = OP_ILLEGAL
		print(f"altered op = {packet.op}")

	if chosenAttack == ATTACK_CHANGE_ACK:
		if packet.block != 1:
			packet.block = packet.block - 1
			print(f"altered ACK num = {packet.block}")

	if chosenAttack == ATTACK_CHANGE_TXT:
		packet.load = TEXT_CHANGED
		print(f"altered text = {packet.load}")

	if chosenAttack == ATTACK_CHANGE_BLOCK:
		packet.block = 3
		print(f"altered block = {packet.block}")

	return packet

def getBytesForPacket(packet):
	size = len(packet.load)
	return size

def packetHasLoad(packet):
	packet_str = packet.show(dump=True)
	return "load" in packet_str

def readingLogic(chosenAttack, data_server_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address):
	if chosenAttack == ATTACK_CHANGE_TXT:
		data_server_mod = applyModRequest(data_server_mod, chosenAttack, mode)

	if chosenAttack == ATTACK_CHANGE_BLOCK:
		data_server_mod = applyModRequest(data_server_mod, chosenAttack, mode)
		data_server_mod_bytes = bytes(data_server_mod)
		fw_proxy_client.sendto(data_server_mod_bytes, client_address)
		print(f"Received data from Server: Server = {server_address} | Data = {data_server_mod_bytes}")
		print(f"Forwarding data to the Client: Client = {client_address}")
		print(f"Waiting for request re-sending from client")

		request, client_address = fw_proxy_client.recvfrom(BUFFER_TFTP)

		request_mod = TFTP(request)
		request_mod_bytes = bytes(request_mod)

		fw_proxy_server.sendto(request_mod_bytes, server_address)
		print(f"Received RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
		print(f"Forwarding rrq to the Server: Server = {server_address}")

		tftp_data_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)
		data_server_mod = TFTP(tftp_data_packet)

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

	if not (chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ):
		if chosenAttack == ATTACK_CHANGE_TXT or oldChosenAttack == ATTACK_CHANGE_TXT:
			return
		ack_packet, client_address = fw_proxy_client.recvfrom(BUFFER_TFTP)
		ack_server_mod = TFTP(ack_packet)
		oldAck = ack_server_mod.block
		if chosenAttack == ATTACK_CHANGE_ACK:
			ack_server_mod = applyModRequest(ack_server_mod, chosenAttack, mode)
		ack_server_mod_bytes = bytes(ack_server_mod)

		if not (chosenAttack == ATTACK_DROP_ACK or chosenAttack == ATTACK_TWICE_ACK):
			fw_proxy_server.sendto(ack_server_mod_bytes, server_address)
			print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
			print(f"Forwarding ack to the Server: Server = {server_address}")

			if chosenAttack == ATTACK_CHANGE_ACK and oldAck != 1:
				print(f"Waiting for re-sending from server")
				tftp_data_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)
				tftp_data_packet_mod = TFTP(tftp_data_packet)
				print(f"Re-sending from server:")
				print(tftp_data_packet_mod)
				print(f"Omitting forwarding to client because packet is already there...")

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

		elif chosenAttack == ATTACK_TWICE_ACK:
			fw_proxy_server.sendto(ack_server_mod_bytes, server_address)
			print(f"Received first ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
			print(f"Forwarding first ack to the Server: Server = {server_address}")

			time.sleep(2) # We wait two seconds to see it clearly

			fw_proxy_server.sendto(ack_server_mod_bytes, server_address)
			print(f"Received second ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
			print(f"Forwarding second ack to the Server: Server = {server_address}")
			print(f"Server does not send answer to second ACK")



def writingLogic(chosenAttack, datapacket_client_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address):
	if chosenAttack == ATTACK_CHANGE_TXT:
		datapacket_client_mod = applyModRequest(datapacket_client_mod, chosenAttack, mode)

	if chosenAttack == ATTACK_CHANGE_BLOCK or chosenAttack == ATTACK_FILE_NOT_FOUND:
		chosenAttack == ATTACK_NO_ATTACK

	datapacket_client_mod_bytes = bytes(datapacket_client_mod)

	fw_proxy_server.sendto(datapacket_client_mod_bytes, server_address)
	print(f"Received Data-Packet from Client: Client = {client_address} | Data = {datapacket_client_mod_bytes}")
	print(f"Forwarding data to the Server: Server = {server_address}")

	if not chosenAttack == ATTACK_TWICE_ACK:
		ack_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		ack_server_mod = TFTP(ack_packet)
		oldAck = ack_server_mod.block
		ack_server_mod_bytes = bytes(ack_server_mod)

		if chosenAttack == ATTACK_CHANGE_ACK:
			ack_server_mod = applyModRequest(ack_server_mod, chosenAttack, mode)

		if chosenAttack == ATTACK_CHANGE_ACK and oldAck != 1:
			print(f"Waiting for re-sending from client")
			tftp_data_packet, server_address = fw_proxy_client.recvfrom(BUFFER_TFTP)
			tftp_data_packet_mod = TFTP(tftp_data_packet)
			print(f"Re-sending from client:")
			print(tftp_data_packet_mod)
			fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
			print(f"Received ACK from the Server: Server = {server_address} | Data = {ack_server_mod_bytes}")
			print(f"Forwarding ack to the Client: Client = {client_address}")

		else:
			fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
			fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
			print(f"Received ACK from the Server: Server = {server_address} | Data = {ack_server_mod_bytes}")



	else:
		ack_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		ack_server_mod = TFTP(ack_packet)
		ack_server_mod_bytes = bytes(ack_server_mod)

		fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
		print(f"Received first ACK from the Server: Server = {server_address} | Data = {ack_server_mod_bytes}")
		print(f"Forwarding first ack to the Client: Client = {client_address}")

		fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
		print(f"Forwarding second ack to the Client: Client = {client_address}")



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

	if chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_ILLEGAL_OP or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ:
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

		if chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ:
			size = SIZE_ERROR_PACK
		else:
			if packetHasLoad(data_server_mod):
				size = getBytesForPacket(data_server_mod)
			else:
				size = MAX_TRANSFER_TFTP

		while size >= MAX_TRANSFER_TFTP:

			readingLogic(chosenAttack, data_server_mod, mode, fw_proxy_client, fw_proxy_server, client_address, server_address)

			if chosenAttack == ATTACK_CHANGE_TXT:
				break

			tftp_data_packet, server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)
			tftp_data_packet = TFTP(tftp_data_packet)

			if packetHasLoad(tftp_data_packet):
				size = getBytesForPacket(tftp_data_packet)
				lastPacketOfChain = True
			else:
				size = 0
				lastPacketOfChain = True

			if chosenAttack != ATTACK_CHANGE_ACK:
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

		if not (chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ):

			datapacket, clientaddress = fw_proxy_client.recvfrom(BUFFER_TFTP)

			datapacket_client_mod = TFTP(datapacket)

			if chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ:
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

				if chosenAttack != ATTACK_CHANGE_ACK:
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
