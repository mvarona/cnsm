import socket

#Create the socket to listen on 192.168.40.80:21
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("192.168.40.80", 21))
server_socket.listen(5)

#Create the socket to forward the data to the server
fw_proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fw_proxy_server.setsockopt(socket.SOL_SOCKET, 25, str("enp0s3.30" + '\0').encode('utf-8'))

#Accept an incoming connection from the Client
fw_proxy_client, client_address = server_socket.accept()
print(f"Connection from {client_address} has been established!")

#Connect to the server
fw_proxy_server.connect(("192.168.30.90", 21))

#Proxy receives welcome message from the server and rorwards it to the client
welcome_message = fw_proxy_server.recv(1024)
print(welcome_message)
fw_proxy_client.send(welcome_message)

#Proxy receives username from client and forwards it to the server
username = fw_proxy_client.recv(1024)
print(username)
fw_proxy_server.send(username)

#Proxy receives password prompt from the server and forwards it to the client
password_prompt = fw_proxy_server.recv(1024)
print(password_prompt)
fw_proxy_client.send(password_prompt)

#Proxy receives password from the client and forwards it to the server
password = fw_proxy_client.recv(1024)
print(password)
fw_proxy_server.send(password)

#Proxy receives login message from the server and forwards it to the client
login_message = fw_proxy_server.recv(1024)
print(login_message)
fw_proxy_client.send(login_message)

while True:
	print(f"Waiting for a message from client")
	message = fw_proxy_client.recv(1024)
	print(message)
	fw_proxy_server.send(message)
	print(f"Waiting for a message from the server")
	message = fw_proxy_server.recv(1024)
	print(message)
	fw_proxy_client.send(message)

#server_socket.close()
#fw_proxy_server.close()