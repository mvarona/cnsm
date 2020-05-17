import socket


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

# Functions:

def send(socket, msg):
	print("===>sending: " + msg)
	msgBytes = (msg + "\r\n").encode('utf-8')
	msgBytes = bytes(msgBytes)
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
	print("2\tFile not found on put\t\tReturn error code 550")
	print("3\tUnknown command\t\t\tReturn error code 500")
	print("4\tSyntax error in parameter\tReturn error code 501")
	print("5\tChange username\t\t\tReturn error code 530")
	print("6\tDrop ACK packet handshake\tConnection timed out")
	print("7\tDrop ACK packet\t\t\tLast client-packet retransmitted")
	print("8\tDrop server packet\t\tLast server-packet retransmitted")
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

def prepareClientCommand(command):
	print(command)
	if "ls" in command:
		print("ENTERS IN")
		command = command.replace("ls", "LIST")

	return command

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

#Proxy receives welcome message from the server and rorwards it to the client
welcome_message = fw_proxy_server.recv(BUFFER_FTP)
print(welcome_message)
fw_proxy_client.send(welcome_message)

#Proxy receives username from client and forwards it to the server
username = fw_proxy_client.recv(BUFFER_FTP)
print(username)
fw_proxy_server.send(username)

#Proxy receives password prompt from the server and forwards it to the client
password_prompt = fw_proxy_server.recv(BUFFER_FTP)
print(password_prompt)
fw_proxy_client.send(password_prompt)

#Proxy receives password from the client and forwards it to the server
password = fw_proxy_client.recv(BUFFER_FTP)
print(password)
fw_proxy_server.send(password)

#Proxy receives login message from the server and forwards it to the client
login_message = fw_proxy_server.recv(BUFFER_FTP)
print(login_message)
fw_proxy_client.send(login_message)

while True:
	print(f"Waiting for a message from the client")
	pasv_message = fw_proxy_client.recv(BUFFER_FTP)
	pasv_message_str = str(pasv_message)
	fw_proxy_server.send(pasv_message)
	print(f"Waiting for a message from the server")
	passv_answer = fw_proxy_server.recv(BUFFER_FTP)
	passv_answer_string = str(passv_answer)

	if FTP_PASSV_SERVER_CODE in passv_answer_string:
		start = passv_answer_string.find("(")
		end = passv_answer_string.find(")")
		tuple = passv_answer_string[start+1:end].split(',')
		port = int(tuple[4])*256 + int(tuple[5])

		dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		dataSocket.connect((IP_SERVER, port))
		data_answer = send(fw_proxy_server, prepareClientCommand(pasv_message_str))
		data_answer = dataSocket.recv(BUFFER_FTP * 2)
		print(f"Message2: {data_answer}")
		fw_proxy_client.send(data_answer)

		dataSocket.close()


	print(passv_answer)
	fw_proxy_client.send(passv_answer)

#server_socket.close()
#fw_proxy_server.close()
