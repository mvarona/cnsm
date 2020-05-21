import socket

#Create the socket to forward the data to the server
fw_proxy_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fw_proxy_server.setsockopt(socket.SOL_SOCKET, 25, str("enp0s3.30" + '\0').encode('utf-8'))

#Connect to the server
fw_proxy_server.connect(("192.168.30.90", 21))

#Proxy receives welcome message from the server and rorwards it to the client
welcome_message = fw_proxy_server.recv(1024)
print(welcome_message)

#Proxy receives username from client and forwards it to the server

fw_proxy_server.send("ftpuser")

#Proxy receives password prompt from the server and forwards it to the client
password_prompt = fw_proxy_server.recv(1024)
print(password_prompt)

#Proxy receives password from the client and forwards it to the server
fw_proxy_server.send("ftpuser")

#Proxy receives login message from the server and forwards it to the client
login_message = fw_proxy_server.recv(1024)
print(login_message)

while True:
	print(f"Waiting for a message from client")
	fw_proxy_server.send(bytes("LIST".encode('utf-8')))
	print("Sent list")
	print(f"Waiting for a message from the server")
	message = fw_proxy_server.recv(1024)
	print(message)
#server_socket.close()
#fw_proxy_server.close()