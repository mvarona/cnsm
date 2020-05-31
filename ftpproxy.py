import socket
from scapy.all import *
import re
import time

# Constants:

FTP_CONTROL_PORT = 21 # FTP works over TCP on its port 21
FTP_DATA_PORT = 20 # FTP works over TCP on its port 20
IP_CLIENT = "192.168.40.50"
IP_PROXY_CLIENT = "192.168.40.80"
IP_PROXY_SERVER = "192.168.30.80"
IP_SERVER = "192.168.30.90"
INTERFACE_PROXY_CLIENT = "enp0s3.30"
BUFFER_FTP = 1024
MIN_ATTACK_NUM = 0
MAX_ATTACK_NUM = 10

ATTACK_NO_ATTACK = 0
ATTACK_FILE_NOT_FOUND = 1
ATTACK_DROP_PACK = 2
ATTACK_ALTER_RES = 3
ATTACK_SEND_QUIT = 4
ATTACK_CHANGE_USER = 5
ATTACK_DROP_PACK_HSK = 6
ATTACK_TWICE_ACK = 7
ATTACK_CHANGE_DATA_PORT = 8
ATTACK_TWICE_DATA = 9
ATTACK_UNKNOWN_COMMAND = 10

USER_NONEXISTENT = "USER_NONEXISTENT\r\n"
COMMAND_QUIT = "QUIT"
COMMAND_PORT = "PORT"
COMMAND_TYPE = "TYPE I"
COMMAND_PUT = "STOR"
FILE_NONEXISTENT = "nothing.txt"
TEXT_ALTERED = "!!!THIS TEXT WAS ALTERED!!!\n"
COMMAND_UNKNOWN = "CMD"
MINIMUM_SCAPY_SIZE_PACKET = 5
NO_FILE_SCAPY_SIZE_PACKET = -1
FTP_GET = "RETR "
FTP_PUT = "STOR "

# Functions:

def sendMsg(socket, msg):
	print("===>sending: " + msg)
	msgBytes = (msg + "\r\n").encode('utf-8')
	socket.send(msgBytes)
	recv = socket.recv(BUFFER_FTP)
	print("<===receive: " + str(recv))
	return recv

def showInitialMenu():
	print("*** Welcome to ftpproxuy ***")
	print("Please, choose one of the following attacks to be carried out:")
	print("")
	print("#\tError scenario\t\t\tExpected result")
	print("")
	print("0\tNo error\t\t\tNormal working")
	print("1\tFile not found (GET)\t\tReturn error code 550")
	print("2\tDrop data packet\t\tOther part re-sends packet")
	print("3\tAlter result\t\t\tReturn fake result")
	print("4\tSend quit command\t\tFinish connection")
	print("5\tChange username\t\t\tReturn error code 530")
	print("6\tDrop packet in handshake\tConnection hanged out")
	print("7\tSend twice ACK\t\t\tWindow size is decreased")
	print("8\tSend data to wrong port\t\tConnection refused")
	print("9\tSend twice data\t\t\tAccept extra data")
	print("10\tUnknown command\t\t\tError 500")
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

def applyMod(packet, chosenAttack, fileSize, mode):

	if chosenAttack == ATTACK_FILE_NOT_FOUND:
		packet.load = str(packet.load)[2] + FILE_NONEXISTENT

	if chosenAttack == ATTACK_ALTER_RES:
		if fileSize != NO_FILE_SCAPY_SIZE_PACKET and fileSize > MINIMUM_SCAPY_SIZE_PACKET:
			packet.load = TEXT_ALTERED
		else:
			packet = bytes(TEXT_ALTERED.encode('utf-8'))

	if chosenAttack == ATTACK_CHANGE_USER:
		packet.load = USER_NONEXISTENT

	if chosenAttack == ATTACK_SEND_QUIT:
		packet.load = COMMAND_QUIT

	return packet

def getFileSize(packet):

	command = str(packet)
	# Assuming filename includes its size in bytes:
	size = re.findall("\d+", command)
	if len(size) != 0:
		size = size[0]
	else:
		# Fallback for LIST command:
		size = NO_FILE_SCAPY_SIZE_PACKET
	size = int(size)
	return size

def buildMockPacket(packet):

	print(f"Incoming packet:")
	packet.show()
	print(f"Altered built packet:")
	packet = packet.__class__(str(packet))
	packet.load = "LIST"
	packet.sport = 12850
	packet.dport = 12320
	packet = TCP(packet)
	packet.show()

	return packet


# Entry point:

chosenAttack = chooseAttack()

#Create the socket to listen on 192.168.40.80:21
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((IP_PROXY_CLIENT, FTP_CONTROL_PORT))
server_socket.listen(1)

#Create the socket to forward the data to the server
fw_proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fw_proxy_server.setsockopt(socket.SOL_SOCKET, 25, str(INTERFACE_PROXY_CLIENT + '\0').encode('utf-8'))

#Accept an incoming connection from the Client
fw_proxy_client, client_address = server_socket.accept()
print(f"Connection from {client_address} has been established!")

#Connect to the server
fw_proxy_server.connect((IP_SERVER, FTP_CONTROL_PORT))

#Proxy receives welcome message from the server and forwards it to the client
welcome_message = fw_proxy_server.recv(BUFFER_FTP)
welcome_messageFTP = TCP(welcome_message)
welcome_messageFTP_bytes = bytes(welcome_messageFTP)
print(welcome_message)
fw_proxy_client.send(welcome_messageFTP_bytes)

#Proxy receives username from client and forwards it to the server
username = fw_proxy_client.recv(BUFFER_FTP)
usernameFTP = UDP(username)

if chosenAttack == ATTACK_CHANGE_USER:
	usernameFTP = applyMod(usernameFTP, chosenAttack, None, None)

usernameFTP_bytes = bytes(usernameFTP)
print(usernameFTP_bytes)
print(username)
fw_proxy_server.send(usernameFTP_bytes)

#Proxy receives password prompt from the server and forwards it to the client
password_prompt = fw_proxy_server.recv(BUFFER_FTP)
password_promptFTP = TCP(password_prompt)
password_promptFTP_bytes = bytes(password_promptFTP)
print(password_prompt)
fw_proxy_client.send(password_promptFTP_bytes)

#Proxy receives password from the client and forwards it to the server

password = fw_proxy_client.recv(BUFFER_FTP)
passwordFTP = TCP(password)
passwordFTP_bytes = bytes(passwordFTP)
print(password)

if chosenAttack == ATTACK_DROP_PACK_HSK:
	print(f"Ommiting forwarding password to server")
	print(f"Waiting for re-sending from client (won't happen)")
	password = fw_proxy_client.recv(BUFFER_FTP)
	passwordFTP = TCP(password)
	passwordFTP_bytes = bytes(passwordFTP)

fw_proxy_server.send(passwordFTP_bytes)

#Proxy receives login message from the server and forwards it to the client
login_message = fw_proxy_server.recv(BUFFER_FTP)
login_messageFTP = TCP(login_message)
login_messageFTP_bytes = bytes(login_messageFTP)
print(login_message)
fw_proxy_client.send(login_messageFTP_bytes)

keepRunning = True
while keepRunning == True:
	print(f"Waiting for a message from the client")
	message = fw_proxy_client.recv(BUFFER_FTP)
	message_string = str(message)
	print(message)
	fw_proxy_server.send(message)
	print(f"Waiting for a message from the server")
	answer = fw_proxy_server.recv(BUFFER_FTP)
	print(answer)
	answer_string = str(answer)
	fw_proxy_client.send(answer)

	if COMMAND_QUIT in message_string:
		fw_proxy_server.send(message)
		print(f"Waiting for a message from the server")
		answer = fw_proxy_server.recv(BUFFER_FTP)
		print(answer)
		answer_string = str(answer)
		fw_proxy_client.send(answer)
		keepRunning = False
	else:

		print(f"Waiting for a message from the client")
		message = fw_proxy_client.recv(BUFFER_FTP)
		print(message)
		message_string = str(message)

		if COMMAND_QUIT in message_string:
			fw_proxy_server.send(message)
			print(f"Waiting for a message from the server")
			answer = fw_proxy_server.recv(BUFFER_FTP)
			print(answer)
			answer_string = str(answer)
			fw_proxy_client.send(answer)
			keepRunning = False

		if keepRunning == True:

			if COMMAND_TYPE in message_string:
				fw_proxy_server.send(message)
				print(f"Waiting for a message from the server")
				answer = fw_proxy_server.recv(BUFFER_FTP)
				print(answer)
				answer_string = str(answer)
				fw_proxy_client.send(answer)
				print(f"Waiting for a message from the client")
				message = fw_proxy_client.recv(BUFFER_FTP)
				print(message)
				message_string = str(message)

			port = 0

			if COMMAND_PORT in str(message):
				start = str(message).find("(")
				end = str(message).find(")")
				tuple = str(message)[start+1:end].split(',')
				first = int(tuple[4])
				second = int(tuple[5].replace("\\r\\n", ""))
				port = int(first)*256 + int(second)

				if chosenAttack == ATTACK_CHANGE_DATA_PORT:
					port = int(second)*256 + int(first)

				#Create the socket to listen on 192.168.30.80:port
				server_socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				server_socket2.bind(('192.168.30.80', port))
				server_socket2.listen(1)
				print(f"Listening on {port}")
				answer = sendMsg(fw_proxy_server, "PORT 192,168,30,80," + tuple[4] + "," + tuple[5])
				print(f"Waiting for a message from the server to the PORT message")
				print(answer) # 200 PORT command successful
				fw_proxy_client.send(answer)

			#Create the socket to forward the data to the server

			print(f"Waiting for a request from the client") # REQUEST: LIST / GET / PUT
			message = fw_proxy_client.recv(BUFFER_FTP)

			if chosenAttack == ATTACK_TWICE_ACK:
				message_mod = TCP(message)
			else:
				message_mod = UDP(message)

			fileSize = getFileSize(message_mod)
			mode = None

			if FTP_GET in str(message):
				mode = FTP_GET
			if FTP_PUT in str(message):
				mode = FTP_PUT

			if chosenAttack == ATTACK_FILE_NOT_FOUND:
				message_mod = applyMod(message_mod, chosenAttack, fileSize, mode)

			if chosenAttack == ATTACK_TWICE_ACK:
				print(f"Sending second ACK to client")
				sport = message_mod.sport
				dport = message_mod.dport
				lastAck = message_mod.ack
				lastSeq = message_mod.seq

				ip = IP(src=IP_PROXY_CLIENT, dst=IP_CLIENT)
				ack = TCP(sport=sport, dport=FTP_CONTROL_PORT, flags='A', seq=lastAck, ack=lastSeq)
				send(ip/ack)
				print(f"Client accepts DUP ACK")

			message_string = str(message_mod)
			message_mod_bytes = bytes(message_mod)
			print(message_mod)
			print(f"Forwarding request to server")

			if chosenAttack == ATTACK_SEND_QUIT or chosenAttack == ATTACK_FILE_NOT_FOUND:
				newLoad = ""
				if fileSize != NO_FILE_SCAPY_SIZE_PACKET and fileSize > MINIMUM_SCAPY_SIZE_PACKET:
					newLoad = str(message_mod.load)
				else:
					newLoad = str(message_mod)

				if mode == FTP_GET:
					newLoad = FTP_GET + newLoad[2:-1]
				if mode == FTP_PUT:
					newLoad = FTP_PUT + newLoad[2:-1]

				if chosenAttack == ATTACK_FILE_NOT_FOUND:
					answer = sendMsg(fw_proxy_server, newLoad)
				elif chosenAttack == ATTACK_SEND_QUIT:
					answer = sendMsg(fw_proxy_server, COMMAND_QUIT)
					keepRunning = False

				print(f"Waiting for a message from the server")
				print(answer)
				fw_proxy_client.send(answer)

			elif chosenAttack == ATTACK_CHANGE_DATA_PORT:
				fw_proxy_server.send(message_mod_bytes)
				print(f"Sent packet with unknown port")
				print(f"Waiting for an answer from the server")
				answer = fw_proxy_server.recv(BUFFER_FTP)
				print(answer)

			elif chosenAttack == ATTACK_UNKNOWN_COMMAND:
				answer = sendMsg(fw_proxy_server, COMMAND_UNKNOWN)
				print(f"Sent packet with unknown command")
				print(f"Waiting for an answer from the server")
				print(answer)
				print(f"Forwarding answer to client")
				fw_proxy_client.send(answer)

			else:
				fw_proxy_server.send(message_mod_bytes)

				if COMMAND_PUT in message_string:

					#Create the socket to forward the data to the server
					fw_proxy_server2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

					#Create the socket to receive the data from the client
					fw_proxy_client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

					#Accept an incoming connection from the Server
					fw_proxy_server2, data_address = server_socket2.accept()
					print(f"Connection from {data_address} has been established!")

					print(f"Waiting for an answer from the server") # Response 150: Opening ASCII mode
					answer = fw_proxy_server.recv(BUFFER_FTP)
					print(answer)
					fw_proxy_client.send(answer)

					fw_proxy_client2.connect((IP_CLIENT, port))
					print(f"Waiting for data from client")

					data_mod = fw_proxy_client2.recv(BUFFER_FTP)

					if fileSize != NO_FILE_SCAPY_SIZE_PACKET and fileSize > MINIMUM_SCAPY_SIZE_PACKET:
						data_mod = UDP(data_mod)

					data_mod = applyMod(data_mod, chosenAttack, fileSize, mode)
					data_mod_bytes = bytes(data_mod)
					print(data_mod)

					if chosenAttack == ATTACK_DROP_PACK:
						print(f"Omitting forwarding to server...")
						print(f"Waiting for re-sending from client")
						data = fw_proxy_client2.recv(BUFFER_FTP)

					print(f"Forwarding received data to server")
					fw_proxy_server2.send(data_mod_bytes)

					if chosenAttack == ATTACK_TWICE_DATA:
						print(f"Forwarding for second time received data to server")
						fw_proxy_server2.send(data_mod_bytes)
						print(f"Waiting for answer from client")
						data = fw_proxy_client2.recv(BUFFER_FTP)
						print(data)

				else:
					fw_proxy_server2, data_address = server_socket2.accept()
					print(f"Connected from {data_address}")

					print(f"Waiting for an answer from the server") # Response 150: Opening ASCII mode
					answer = fw_proxy_server.recv(BUFFER_FTP)
					print(answer)
					fw_proxy_client.send(answer)

					print(f"Waiting for data from server")
					data_mod = fw_proxy_server2.recv(BUFFER_FTP)

					if fileSize != NO_FILE_SCAPY_SIZE_PACKET and fileSize > MINIMUM_SCAPY_SIZE_PACKET:
						data_mod = UDP(data_mod)

					if chosenAttack == ATTACK_ALTER_RES:
						data_mod = applyMod(data_mod, chosenAttack, fileSize, mode)
					data_mod_bytes = bytes(data_mod)
					print(data_mod)

					#Create the socket to forward the data to the client
					fw_proxy_client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					fw_proxy_client2.connect((IP_CLIENT, port))

					if chosenAttack == ATTACK_DROP_PACK:
						print(f"Omitting forwarding to client...")
						print(f"Waiting for re-sending from server")
						data = fw_proxy_server2.recv(BUFFER_FTP)

					print(f"Forwarding received data to client")
					fw_proxy_client2.send(data_mod_bytes)

					if chosenAttack == ATTACK_TWICE_DATA:
						print(f"Forwarding for second time received data to client")
						fw_proxy_client2.send(data_mod_bytes)
						print(f"Waiting for answer from server")
						data = fw_proxy_server2.recv(BUFFER_FTP)
						print(data)

				print(f"Waiting for 226 from the server")
				message = fw_proxy_server.recv(BUFFER_FTP)
				print(message)
				fw_proxy_client.send(message)

				server_socket2.close()
				fw_proxy_server2.close()
				fw_proxy_client2.close()

	if keepRunning == False:
		fw_proxy_client.close()
		fw_proxy_server.close()
		server_socket.close()
