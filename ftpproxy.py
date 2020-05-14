import socket


# Constants:

FTP_CONTROL_PORT = 21 # FTP works over TCP on its port 21
FTP_DATA_PORT = 20 # FTP works over TCP on its port 20
IP_PROXY = "192.168.40.80"
IP_SERVER = "192.168.30.90"
INTERFACE_NETWORK_PROXY = "enp0s3.30"
BUFFER_FTP = 1024
FTP_PASSV_SERVER_CODE = "227" #FTP sends status code 227 in response to a passive request from client

# Functions:

def send(socket, msg):
	print("===>sending: " + msg)
	msgBytes = (msg + "\r\n").encode('utf-8')
	msgBytes = bytes(msgBytes)
	socket.send(msgBytes)
	recv = socket.recv(BUFFER_FTP)
	print("<===receive: " + str(recv))
	return recv

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
	message = fw_proxy_client.recv(BUFFER_FTP)
	print(message)
	fw_proxy_server.send(message)
	print(f"Waiting for a message from the server")
	message = fw_proxy_server.recv(BUFFER_FTP)
	message_string = str(message)

	if FTP_PASSV_SERVER_CODE in message_string:
		start = message_string.find("(")
		end = message_string.find(")")
		tuple = message_string[start+1:end].split(',')
		port = int(tuple[4])*256 + int(tuple[5])

		dataSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		dataSocket.connect((IP_SERVER, port))
		message2 = send(fw_proxy_server, "LIST")
		message2 = dataSocket.recv(BUFFER_FTP * 2)
		print(f"Message2: {message2}")
		fw_proxy_client.send(message2)

		dataSocket.close()


	print(message)
	fw_proxy_client.send(message)

#server_socket.close()
#fw_proxy_server.close()
