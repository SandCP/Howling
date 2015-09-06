import socket
import hashlib


class Howling:
	def __init__(self,addr, service,showops):
		self.addr = addr
		self.service = service
		self.showops = showops
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((self.addr,self.service))

	# cryptographic functions
	# club penguin uses a weird hashing technique

	def cpencode(self,password):
		hash = hashlib.md5(password).hexdigest()
		print hash
		swap = hash[16:32] + hash[0:16]
		return swap

	def gethash(self,password,rndk):
		return self.cpencode(self.cpencode(password).upper()+rndk+"a1ebe00441f5aecb185d0ec178ca2305Y(02.>'H}t\":E1_root")

	def revi(self):
		buf = self.sock.recv(4096)
		try:
			while(buf):
				buf = self.sock.recv(4096)
				return buf
		except:
			print

	def keyret(self,buf):
		i = buf[len("<k>"):-len("</k>")]
		return i

	def login(self,user,password,rkey):
		self.user = user
		self.password = password
		self.rkey = rkey
		self.p = self.gethash(self.password,self.rkey)
		self.sock.send('<msg t="sys"><body action="login" r="0"><login z="w1"><nick><![CDATA['+self.user+']]></nick><pword><![CDATA['+self.p+']]></pword></login></body></msg>' + chr(0))

	def handshake(self,user,password,apirev=153):
		baf = self.revi()
		while baf:
			baf = self.revi()
			if('policy' in baf):
				if self.showops:
					print "[+] Handshaking server."
				self.sock.send('<msg t="sys"><body action="verChk" r="0"><ver v="153"/></body></msg>'+chr(0))
			if('apiOK' in baf):
				if self.showops:
					print "[+] API returned 'apiOK' response."
					print "[+] Sending rndK request."
				self.sock.send('<msg t="sys"><body action="rndK" r="-1"></body></msg>'+chr(0))
			elif('apiKO' in baf):
				if self.showops:
					print "[-] API returned 'apiKO' response."
				return false
				break
			if('rndK' in baf):
				if self.showops:
					print "[+] Key sent to client, returning."
					print "[+] Key: ".self.keyret(baf)
				key = self.keyret(baf)
				self.sock.send(key+chr(0))
				self.login(user, password,key)
			if('%l' in baf):
				if self.showops:
					print "[+] Logged in to login server."
				return baf
