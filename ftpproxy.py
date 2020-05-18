import socket
from scapy.all import *

# Constants:

FTP_CONTROL_PORT = 21 # FTP works over TCP on its port 21
FTP_DATA_PORT = 20 # FTP works over TCP on its port 20
IP_PROXY = "192.168.40.80"
IP_SERVER = "192.168.30.90"
INTERFACE_NETWORK_PROXY = "enp0s3.30"
BUFFER_FTP = 1024
FTP_PASSV_SERVER_CODE = "227" #FTP sends status code 227 in response to a passive request from client
MIN_ATTACK_NUM = 0
MAX_ATTACK_NUM = 10

ATTACK_NO_ATTACK = 0
ATTACK_FILE_NOT_FOUND_GET = 1
ATTACK_TWICE_CTRL = 2
ATTACK_UNKNOWN_COMMAND = 3
ATTACK_SEND_BYE = 4
ATTACK_CHANGE_USER = 5
ATTACK_DROP_PACK_HSK = 6
ATTACK_DROP_ACK = 7
ATTACK_CHANGE_DATA_PORT = 8
ATTACK_TWICE_ACK = 9
ATTACK_THRICE_ACK = 10

USER_NONEXISTENT = "USER_NONEXISTENT\r\n"

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
	print("3\tUnknown command\t\t\tReturn error code 500")
	print("4\tSend bye command\tFinish connection")
	print("5\tChange username\t\t\tReturn error code 530")
	print("6\tDrop packet in handshake\tConnection hanged out")
	print("7\tDrop ACK packet\t\t\tLast client-packet retransmitted")
	print("8\tSend data to wrong port\tConnection refused")
	print("9\tDuplicate ACK\t\t\tDo nothing")
	print("10\tTriplicate ACK\t\t\tResend following packet")
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

	if chosenAttack == ATTACK_SEND_BYE:
		packet.seq = 0

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
server_socket.bind((IP_PROXY, FTP_CONTROL_PORT))
server_socket.listen(5)

#Create the socket to forward the data to the server
fw_proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fw_proxy_server.setsockopt(socket.SOL_SOCKET, 25, str(INTERFACE_NETWORK_PROXY + '\0').encode('utf-8'))

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

while True:
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
	messageFTP = UDP(message)
	messageFTP.load = "bye\r\n"
	messageFTP_bytes = bytes(messageFTP)
	print(messageFTP)
	fw_proxy_server.send(messageFTP_bytes)
	print(f"Waiting for a message from the server")
	answer = fw_proxy_server.recv(BUFFER_FTP)
	print(answer)
	answer_string = str(answer)
#	fw_proxy_client.send(answer)

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

		if chosenAttack == ATTACK_CHANGE_DATA_PORT:
			port = int(tuple[5])*256 + int(tuple[4])

		dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		dataSocket.connect((IP_SERVER, port))

		request = send(fw_proxy_server, "LIST")

		if chosenAttack == ATTACK_CHANGE_DATA_PORT:
			print(f"Waiting for a message from the server")
			answer = fw_proxy_server.recv(BUFFER_FTP)
			print(answer)

		#command = IP(src="192.168.30.80", dst=IP_SERVER)/TCP(sport=11000,dport=21)/"LIST"
		#command.show()
		#fw_proxy_server.send(bytes(("LIST").encode('utf-8')))
		answerToRequest = dataSocket.recv(BUFFER_FTP * 2)
		answerToRequestFTP = TCP(answerToRequest)
		answerToRequestFTP_bytes = bytes(answerToRequestFTP)
		print(f"AnswerToRequest: {answerToRequest}")
		fw_proxy_client.send(answerToRequestFTP_bytes)

		dataSocket.close()


	fw_proxy_client.send(answer)

#server_socket.close()
#fw_proxy_server.close()
