import socket

# Target info
IP = "10.10.190.74"
PORT = 1337

# Known plaintext
known_plaintext = 'THM{thisisafakeflag}'

# Connect to server
sock = socket.socket()
sock.connect((IP, PORT))

# Receive XORed hex data
data = sock.recv(2048).decode()
print("[+] Received:", data)

# Extract hex string from the message
prefix = "This XOR encoded text has flag 1: "
hex_string = data.split(prefix)[-1].strip()

# Decode hex to bytes
xored_bytes = bytes.fromhex(hex_string)

# Recover key using known plaintext
key = ''
for i in range(len(known_plaintext)):
    key_char = chr(xored_bytes[i] ^ ord(known_plaintext[i]))
    key += key_char

# The key is repeated every 5 chars
final_key = key[:5]
print("[+] Recovered key:", final_key)

# Wait for prompt
data = sock.recv(2048).decode()
print("[+] Server says:", data)

# Send recovered key
sock.sendall((final_key + '\n').encode())

# Get the final flag
final_response = sock.recv(2048).decode()
print("[+] Final response:\n", final_response)

# Close connection
sock.close()
