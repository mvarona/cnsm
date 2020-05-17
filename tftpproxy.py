import socket
from scapy.all import *
import time

# Constants:

TFTP_PORT = 69 # TFTP works over UDP on its port 69
IP_PROXY = "192.168.40.80"
IP_SERVER = "192.168.30.90"
INTERFACE_NETWORK_PROXY = "enp0s3.30"
POS_OPCODE = 1 # According to RFC 1350, the OPCODE is on the second position (1 in array)
OPCODE_READING = 1
OPCODE_WRITING = 2
BUFFER_TFTP = 1024
MAX_TRANSFER_TFTP = 512
VALUES_IN_LAST_PACKET_TFTP = 1

MIN_ATTACK_NUM = 0
MAX_ATTACK_NUM = 10
ATTACK_NO_ATTACK = 0
ATTACK_FILE_NOT_FOUND = 1
ATTACK_ACCESS_VIOLATION = 2
ATTACK_ILLEGAL_OP = 3
ATTACK_CHANGE_DPORT = 4
ATTACK_FILE_NOT_FOUND_WRQ = 5
ATTACK_DROP_PACKET = 6
ATTACK_DROP_ACK = 7
ATTACK_DROP_ERROR = 8
ATTACK_TWICE_ACK = 9
ATTACK_CHANGE_TXT = 10

FILE_NONEXISTENT = "nonexistent.txt"
FILE_FORBIDDEN = "forbidden.txt"
TEXT_CHANGED = "!!!THIS TEXT WAS ALTERED!!!\n"
UDP_NEW_DPORT = 13
SIZE_ERROR_PACK = 10

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
	print("4\tChange UDP dest. port\tServer accepts new port")
	print("5\tFile not found (WRQ)\tReturn error code 1")
	print("6\tDrop client packet\tClient retransmits request")
	print("7\tDrop ACK client (RRQ)\tServer retransmits last byte")
	print("8\tDrop error packet\tClient retries request")
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
	if chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ or chosenAttack == ATTACK_DROP_ERROR:
		packet.filename = FILE_NONEXISTENT
		print(f"altered filename = {packet.filename}")

	if chosenAttack == ATTACK_ACCESS_VIOLATION:
		packet.filename = FILE_FORBIDDEN
		print(f"altered filename = {packet.filename}")

	if chosenAttack == ATTACK_ILLEGAL_OP:
		if mode == OPCODE_READING:
			packet.op = OPCODE_WRITING
		if mode == OPCODE_WRITING:
			packet.op = OPCODE_READING
		print(f"altered op = {packet.op}")

	if chosenAttack == ATTACK_CHANGE_DPORT:
		packetUDP = UDP(packet)
		print(f"unaltered destination port = {packetUDP.dport}")
		packetUDP.dport = UDP_NEW_DPORT
		print(f"altered destination port = {packetUDP.dport}")
		packetResult = TFTP(packet)/UDP(packetUDP)
		return packetResult

	if chosenAttack == ATTACK_CHANGE_TXT:
		packet.load = TEXT_CHANGED
		print(f"altered text = {packet.load}")

	return packet

def getBytesForPacket(packet):
	size = len(packet.load)
	return size

def countValuesInPacket(packet):
	num = len(vars(tftp_data_packet))
	return num


server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((IP_PROXY, TFTP_PORT))
tftp_server_address = (IP_SERVER, TFTP_PORT)

# Entry point:

chosenAttack = chooseAttack()

# Infinite loop to receive and process messages:

while True:
	
	fw_proxy_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	fw_proxy_server.setsockopt(socket.SOL_SOCKET, 25, str(INTERFACE_NETWORK_PROXY + '\0').encode('utf-8'))
	fw_proxy_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	
	# Waiting for a packet:
	
	print(f"Waiting for rrq/wrq from client")
	request, client_address = server_socket.recvfrom(BUFFER_TFTP)

	mode = request[POS_OPCODE]

	request_mod = TFTP(request)

	if chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_ILLEGAL_OP or chosenAttack == ATTACK_CHANGE_DPORT or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ or chosenAttack == ATTACK_DROP_ERROR:
		request_mod = applyModRequest(request_mod, chosenAttack, mode)

	request_mod_bytes = bytes(request_mod)

	if request[POS_OPCODE] == OPCODE_READING:
		fw_proxy_server.sendto(request_mod_bytes, tftp_server_address)
		print(f"Received RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
		print(f"Forwarding rrq to the Server: Server = {tftp_server_address}")

		tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		data_server_mod = TFTP(tftp_data_packet)
		size = 0

		if chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_ILLEGAL_OP or chosenAttack == ATTACK_CHANGE_DPORT or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ or chosenAttack == ATTACK_DROP_PACKET or chosenAttack == ATTACK_DROP_ERROR:
			size = SIZE_ERROR_PACK
		else:
			size = getBytesForPacket(data_server_mod)

		while size >= MAX_TRANSFER_TFTP:

			if chosenAttack == ATTACK_CHANGE_TXT:
				data_server_mod = applyModRequest(data_server_mod, ATTACK_CHANGE_TXT, mode)

			data_server_mod_bytes = bytes(data_server_mod)

			if not (chosenAttack == ATTACK_DROP_PACKET or chosenAttack == ATTACK_DROP_ERROR):
				fw_proxy_client.sendto(data_server_mod_bytes, client_address)
				print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
				print(f"Forwarding data to the Client: Client = {client_address}")
			else:
				print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
				print(f"Omitting forwarding from server to client")
				print(f"Waiting for re-sending from client")
				request, client_address = server_socket.recvfrom(BUFFER_TFTP)
				request_mod = TFTP(request)

				if chosenAttack == ATTACK_DROP_ERROR:
					request_mod = applyModRequest(request_mod, chosenAttack, mode)

				request_mod_bytes = bytes(request_mod)

				fw_proxy_server.sendto(request_mod_bytes, tftp_server_address)
				print(f"Received RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
				print(f"Forwarding rrq to the Server: Server = {tftp_server_address}")

				tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

				data_server_mod = TFTP(tftp_data_packet)
				data_server_mod_bytes = bytes(data_server_mod)

				fw_proxy_client.sendto(data_server_mod_bytes, client_address)
				print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
				print(f"Forwarding data to the Client: Client = {client_address}")

			if not (chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ or chosenAttack == ATTACK_DROP_ERROR):
				ack_packet, client_address = fw_proxy_client.recvfrom(BUFFER_TFTP)

				ack_server_mod = TFTP(ack_packet)
				ack_server_mod_bytes = bytes(ack_server_mod)

				if not (chosenAttack == ATTACK_DROP_ACK or chosenAttack == ATTACK_TWICE_ACK):
					fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
					print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding ack to the Server: Server = {temp_server_address}")

				elif chosenAttack == ATTACK_DROP_ACK:
					print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Omitting forwarding from client to server")
					print(f"Waiting for re-sending from server")
					tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

					data_server_mod = TFTP(tftp_data_packet)
					data_server_mod_bytes = bytes(data_server_mod)

					fw_proxy_client.sendto(data_server_mod_bytes, client_address)
					print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
					print(f"Forwarding data to the Client: Client = {client_address}")

					ack_server_mod = TFTP(ack_packet)
					ack_server_mod_bytes = bytes(ack_server_mod)

					fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
					print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding ack to the Server: Server = {temp_server_address}")

				elif chosenAttack == ATTACK_TWICE_ACK:
					fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
					print(f"Received first ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding first ack to the Server: Server = {temp_server_address}")

					time.sleep(2) # We wait two seconds to see it clearly
					
					fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
					print(f"Received second ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding second ack to the Server: Server = {temp_server_address}")
					print(f"Server does not send answer to second ACK")

				tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)
				tftp_data_packet = TFTP(tftp_data_packet)

				num = countValuesInPacket(tftp_data_packet)

				if num > VALUES_IN_LAST_PACKET_TFTP:
					size = getBytesForPacket(tftp_data_packet)
				else:
					size = 0

		if size < MAX_TRANSFER_TFTP:

			if size == 0:
				data_server_mod = tftp_data_packet

			if chosenAttack == ATTACK_CHANGE_TXT:
				data_server_mod = applyModRequest(data_server_mod, ATTACK_CHANGE_TXT, mode)

			data_server_mod_bytes = bytes(data_server_mod)

			if not (chosenAttack == ATTACK_DROP_PACKET or chosenAttack == ATTACK_DROP_ERROR):
				fw_proxy_client.sendto(data_server_mod_bytes, client_address)
				print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
				print(f"Forwarding data to the Client: Client = {client_address}")
			else:
				print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
				print(f"Omitting forwarding from server to client")
				print(f"Waiting for re-sending from client")
				request, client_address = server_socket.recvfrom(BUFFER_TFTP)
				request_mod = TFTP(request)

				if chosenAttack == ATTACK_DROP_ERROR:
					request_mod = applyModRequest(request_mod, chosenAttack, mode)

				request_mod_bytes = bytes(request_mod)

				fw_proxy_server.sendto(request_mod_bytes, tftp_server_address)
				print(f"Received RRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
				print(f"Forwarding rrq to the Server: Server = {tftp_server_address}")

				tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

				data_server_mod = TFTP(tftp_data_packet)
				data_server_mod_bytes = bytes(data_server_mod)

				fw_proxy_client.sendto(data_server_mod_bytes, client_address)
				print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
				print(f"Forwarding data to the Client: Client = {client_address}")

			if not (chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ or chosenAttack == ATTACK_DROP_ERROR):
				ack_packet, client_address = fw_proxy_client.recvfrom(BUFFER_TFTP)

				ack_server_mod = TFTP(ack_packet)
				ack_server_mod_bytes = bytes(ack_server_mod)

				if not (chosenAttack == ATTACK_DROP_ACK or chosenAttack == ATTACK_TWICE_ACK):
					fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
					print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding ack to the Server: Server = {temp_server_address}")

				elif chosenAttack == ATTACK_DROP_ACK:
					print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Omitting forwarding from client to server")
					print(f"Waiting for re-sending from server")
					tftp_data_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

					data_server_mod = TFTP(tftp_data_packet)
					data_server_mod_bytes = bytes(data_server_mod)

					fw_proxy_client.sendto(data_server_mod_bytes, client_address)
					print(f"Received data from Server: Server = {temp_server_address} | Data = {data_server_mod_bytes}")
					print(f"Forwarding data to the Client: Client = {client_address}")

					ack_server_mod = TFTP(ack_packet)
					ack_server_mod_bytes = bytes(ack_server_mod)

					fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
					print(f"Received ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding ack to the Server: Server = {temp_server_address}")

				elif chosenAttack == ATTACK_TWICE_ACK:
					fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
					print(f"Received first ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding first ack to the Server: Server = {temp_server_address}")

					time.sleep(2) # We wait two seconds to see it clearly
					
					fw_proxy_server.sendto(ack_server_mod_bytes, temp_server_address)
					print(f"Received second ACK from the Client: Cient = {client_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding second ack to the Server: Server = {temp_server_address}")
					print(f"Server does not send answer to second ACK")



	elif request[POS_OPCODE] == OPCODE_WRITING:

		print(f"Received WRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")

		if not (chosenAttack == ATTACK_DROP_PACKET):
			fw_proxy_server.sendto(request_mod_bytes, tftp_server_address)
			print(f"Forwarding wrq to the Server: Server = {tftp_server_address}")
		else:
			print(f"Omitting forwarding to the Server")
			print(f"Waiting for re-sending from client")
			request, client_address = server_socket.recvfrom(BUFFER_TFTP)
			request_mod = TFTP(request)
			request_mod_bytes = bytes(request_mod)
			print(f"Received WRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
			fw_proxy_server.sendto(request_mod_bytes, tftp_server_address)
			print(f"Forwarding wrq to the Server: Server = {tftp_server_address}")

		ack_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

		ack_server_mod = TFTP(ack_packet)
		ack_server_mod_bytes = bytes(ack_server_mod)

		print(f"Received ACK/error from the Server: Server = {temp_server_address} | Data = {ack_server_mod_bytes}")

		if not chosenAttack == ATTACK_DROP_ERROR:
			fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
			print(f"Forwarding ack/error to the Client: Client = {client_address}")
		else:
			print(f"Omitting forwarding to the Client")
			print(f"Waiting for re-sending from client")
			request, client_address = server_socket.recvfrom(BUFFER_TFTP)
			request_mod = TFTP(request)
			print(f"Received WRQ from the Client: Client = {client_address} | Data = {request_mod_bytes}")
			request_mod = applyModRequest(request_mod, chosenAttack, mode)
			request_mod_bytes = bytes(request_mod)
			fw_proxy_server.sendto(request_mod_bytes, tftp_server_address)
			print(f"Forwarding wrq to the Server: Server = {tftp_server_address}")
			ack_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)
			ack_server_mod = TFTP(ack_packet)
			ack_server_mod_bytes = bytes(ack_server_mod)
			print(f"Received ACK/error from the Server: Server = {temp_server_address} | Data = {ack_server_mod_bytes}")
			fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
			print(f"Forwarding ack/error to the Client: Client = {client_address}")

		if not (chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ or chosenAttack == ATTACK_DROP_ERROR):

			datapacket, clientaddress = fw_proxy_client.recvfrom(BUFFER_TFTP)

			datapacket_client_mod = TFTP(datapacket)

			if chosenAttack == ATTACK_FILE_NOT_FOUND or chosenAttack == ATTACK_ACCESS_VIOLATION or chosenAttack == ATTACK_ILLEGAL_OP or chosenAttack == ATTACK_CHANGE_DPORT or chosenAttack == ATTACK_FILE_NOT_FOUND_WRQ or chosenAttack == ATTACK_DROP_PACKET or chosenAttack == ATTACK_DROP_ERROR:
				size = SIZE_ERROR_PACK
			else:
				size = getBytesForPacket(datapacket_client_mod)

			while size >= MAX_TRANSFER_TFTP:

				if chosenAttack == ATTACK_CHANGE_TXT:
					datapacket_client_mod = applyModRequest(datapacket_client_mod, ATTACK_CHANGE_TXT, mode)

				datapacket_client_mod_bytes = bytes(datapacket_client_mod)

				fw_proxy_server.sendto(datapacket_client_mod_bytes, temp_server_address)
				print(f"Received Data-Packet from Client: Client = {clientaddress} | Data = {datapacket_client_mod_bytes}")
				print(f"Forwarding data to the Server: Server = {temp_server_address}")

				if not chosenAttack == ATTACK_TWICE_ACK:
					ack_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

					ack_server_mod = TFTP(ack_packet)
					ack_server_mod_bytes = bytes(ack_server_mod)

					fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
					print(f"Received ACK from the Server: Server = {temp_server_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding ack to the Client: Client = {client_address}")
				else:
					ack_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

					ack_server_mod = TFTP(ack_packet)
					ack_server_mod_bytes = bytes(ack_server_mod)

					fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
					print(f"Received first ACK from the Server: Server = {temp_server_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding first ack to the Client: Client = {client_address}")

					fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
					print(f"Forwarding second ack to the Client: Client = {client_address}")

				datapacket, clientaddress = fw_proxy_client.recvfrom(BUFFER_TFTP)
				datapacket_client_mod = TFTP(datapacket)
				next = len(vars(datapacket_client_mod))

				if next > VALUES_IN_LAST_PACKET_TFTP:
					size = len(datapacket_client_mod.load)
				else:
					size = 0

			if size < MAX_TRANSFER_TFTP:

				if size == 0:
					datapacket_client_mod = datapacket

				if chosenAttack == ATTACK_CHANGE_TXT:
					datapacket_client_mod = applyModRequest(datapacket_client_mod, ATTACK_CHANGE_TXT, mode)

				datapacket_client_mod_bytes = bytes(datapacket_client_mod)

				fw_proxy_server.sendto(datapacket_client_mod_bytes, temp_server_address)
				print(f"Received Data-Packet from Client: Client = {clientaddress} | Data = {datapacket_client_mod_bytes}")
				print(f"Forwarding data to the Server: Server = {temp_server_address}")

				if not chosenAttack == ATTACK_TWICE_ACK:
					ack_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

					ack_server_mod = TFTP(ack_packet)
					ack_server_mod_bytes = bytes(ack_server_mod)

					fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
					print(f"Received ACK from the Server: Server = {temp_server_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding ack to the Client: Client = {client_address}")
				else:
					ack_packet, temp_server_address = fw_proxy_server.recvfrom(BUFFER_TFTP)

					ack_server_mod = TFTP(ack_packet)
					ack_server_mod_bytes = bytes(ack_server_mod)

					fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
					print(f"Received first ACK from the Server: Server = {temp_server_address} | Data = {ack_server_mod_bytes}")
					print(f"Forwarding first ack to the Client: Client = {client_address}")

					fw_proxy_client.sendto(ack_server_mod_bytes, client_address)
					print(f"Forwarding second ack to the Client: Client = {client_address}")