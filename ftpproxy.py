import socket
from scapy.all import *

# Constants:

FTP_CONTROL_PORT = 21 # FTP works over TCP on its port 21
FTP_DATA_PORT = 20 # FTP works over TCP on its port 20
IP_CLIENT = "192.168.40.50"
IP_PROXY_CLIENT = "192.168.40.80"
IP_PROXY_SERVER = "192.168.30.80"
IP_SERVER = "192.168.30.90"
INTERFACE_PROXY_CLIENT = "enp0s3.30"
BUFFER_FTP = 1024
FTP_PASSV_SERVER_CODE = "227" #FTP sends status code 227 in response to a passive request from client
MIN_ATTACK_NUM = 0
MAX_ATTACK_NUM = 10

ATTACK_NO_ATTACK = 0
ATTACK_FILE_NOT_FOUND_GET = 1
ATTACK_TWICE_CTRL = 2
ATTACK_ALTER_LIST = 3
ATTACK_SEND_QUIT = 4
ATTACK_CHANGE_USER = 5
ATTACK_DROP_PACK_HSK = 6
ATTACK_CHANGE_CHK = 7
ATTACK_CHANGE_DATA_PORT = 8
ATTACK_TWICE_LIST = 9
ATTACK_UNEXPECTED_COMMAND = 10

USER_NONEXISTENT = "USER_NONEXISTENT\r\n"
COMMAND_EXIT = "QUIT"
COMMAND_PORT = "PORT"
FILE_NONEXISTENT = "nonexistent.txt"
ERROR_FILE_NOT_FOUND_GET = "550 Permission denied (No such file or folder)\r\n"
ERROR_UNEXPECTED_COMMAND = "500 List malformed not understood\r\n"

# Functions:

def send(socket, msg):
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
	print("1\tFile not found on get\t\tReturn error code 550")
	print("2\tSend twice PASV message\t\tServer returns different port")
	print("3\tAlter result list (ls)\t\tReturn fake result")
	print("4\tSend quit command\t\tFinish connection")
	print("5\tChange username\t\t\tReturn error code 530")
	print("6\tDrop packet in handshake\tConnection hanged out")
	print("7\tChange checksum\t\t\tPacket is corrupted")
	print("8\tSend data to wrong port\t\tConnection refused")
	print("9\tDuplicate result list (ls)\tAccept re-sending")
	print("10\tUnexpected arguments\t\tError")
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

def applyMod(packet, chosenAttack):
	if chosenAttack == ATTACK_CHANGE_USER:
		packet.load = USER_NONEXISTENT

	if chosenAttack == ATTACK_ALTER_LIST:
		packet.load = FILE_NONEXISTENT + "\r\n"

	if chosenAttack == ATTACK_SEND_QUIT:
		packet.load = COMMAND_QUIT

	if chosenAttack == ATTACK_CHANGE_CHK:
		packet.show()
		packet.ack = 0
		packet.seq = 0
		packet.dport = 1230
		packet.chksum = 0
		packet.show()

	return packet

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
	usernameFTP = applyMod(usernameFTP, chosenAttack)

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
	print(message)
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
	if COMMAND_EXIT in message_string:
		keepRunning = False
		break

	port = 0

	if COMMAND_PORT in str(message):
		start = str(message).find("(")
		end = str(message).find(")")
		tuple = str(message)[start+1:end].split(',')
		first = int(tuple[4])
		second = int(tuple[5].replace("\\r\\n", ""))
		port = int(first)*256 + int(second)

		#Create the socket to listen on 192.168.30.80:port
		server_socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket2.bind(('192.168.30.80', port))
		server_socket2.listen(1)
		print(f"Listening on {port}")
		answer = send(fw_proxy_server, "PORT 192,168,30,80," + tuple[4] + "," + tuple[5])
		print(f"Waiting for a message from the server to the PORT message")
		print(answer) # 200 PORT command successful
		fw_proxy_client.send(answer)

	#Create the socket to forward the data to the server

	print(f"Waiting for a request from the client") # REQUEST: LIST
	message = fw_proxy_client.recv(BUFFER_FTP)
	print(message)
	fw_proxy_server.send(message)

	fw_proxy_server2, data_address = server_socket2.accept()
	print(f"Connected from {data_address}")

	print(f"Waiting for an answer from the server") # Response 150: Opening ASCII mode
	answer = fw_proxy_server.recv(BUFFER_FTP)
	print(answer)
	fw_proxy_client.send(answer)

	print(f"Waiting for data from server")
	data = fw_proxy_server2.recv(BUFFER_FTP)
	print(data)

	#Create the socket to forward the data to the client
	fw_proxy_client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	fw_proxy_client2.connect((IP_CLIENT, port))
	fw_proxy_client2.send(data)

	print(f"Waiting for 226 from the server")
	message = fw_proxy_server.recv(BUFFER_FTP)
	print(message)
	fw_proxy_client.send(message)

	server_socket2.close()
	fw_proxy_server2.close()
	fw_proxy_client2.close()

	fw_proxy_client.close()
	fw_proxy_server.close()
	server_socket.close()
	keepRunning = False

	if chosenAttack == ATTACK_TWICE_CTRL:
		print(f"Sending again client message:")
		print(message)
		fw_proxy_server.send(message)
		print(f"Waiting for a message from the server")
		answer = fw_proxy_server.recv(BUFFER_FTP)
		print(answer)

	if FTP_PASSV_SERVER_CODE in answer_string:
		start = answer_string.find("(")
		end = answer_string.find(")")
		tuple = answer_string[start+1:end].split(',')
		port = int(tuple[4])*256 + int(tuple[5])

		#Accept an incoming connection from the Client
		fw_proxy_client2, client_address2 = server_socket.accept()
		print(f"Connection from {client_address2} has been established!")

		print(f"Here Waiting for a message from the client")
		message = fw_proxy_client2.recv(BUFFER_FTP)
		print(message)
		fw_proxy_server.send(message)

		if chosenAttack == ATTACK_CHANGE_DATA_PORT:
			port = int(tuple[5])*256 + int(tuple[4])

		dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		dataSocket.connect((IP_SERVER, port))

		if chosenAttack == ATTACK_SEND_QUIT:
			request = send(fw_proxy_server, COMMAND_QUIT)
		elif chosenAttack == ATTACK_FILE_NOT_FOUND_GET:
			request = send(fw_proxy_server, "GET " + FILE_NONEXISTENT + "\r\n")
		elif chosenAttack == ATTACK_UNEXPECTED_COMMAND:
			request = send(fw_proxy_server, "LIST_MALFORMED" + "\r\n")
		else:
			request = send(fw_proxy_server, "LISTA")

		if chosenAttack == ATTACK_CHANGE_DATA_PORT:
			print(f"Waiting for a message from the server")
			answer = fw_proxy_server.recv(BUFFER_FTP)
			print(answer)

		#command = IP(src="192.168.30.80", dst=IP_SERVER)/TCP(sport=11000,dport=21)/"LIST"
		#command.show()
		#fw_proxy_server.send(bytes(("LIST").encode('utf-8')))

		if chosenAttack == ATTACK_FILE_NOT_FOUND_GET:
			error = ERROR_FILE_NOT_FOUND_GET
			fw_proxy_client.send(bytes((error).encode('utf-8')))

		elif chosenAttack == ATTACK_UNEXPECTED_COMMAND:
			error = ERROR_UNEXPECTED_COMMAND
			fw_proxy_client.send(bytes((error).encode('utf-8')))
		else:
			answerToRequest = dataSocket.recv(BUFFER_FTP * 2)
			answerToRequestFTP = TCP(answerToRequest)

			if chosenAttack == ATTACK_ALTER_LIST:
				answerToRequestFTP = applyMod(answerToRequestFTP, chosenAttack)

			if chosenAttack == ATTACK_CHANGE_CHK:
				answerToRequestFTP = applyMod(answerToRequestFTP, chosenAttack)

			answerToRequestFTP_bytes = bytes(answerToRequestFTP)
			print(f"AnswerToRequest: {answerToRequest}")
			fw_proxy_client.send(answerToRequestFTP_bytes)

			if chosenAttack == ATTACK_TWICE_LIST:
				fw_proxy_client.send(answerToRequestFTP_bytes)

		dataSocket.close()

server_socket.close()
fw_proxy_server.close()
fw_proxy_client.close()
