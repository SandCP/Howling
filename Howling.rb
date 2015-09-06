=begin
 Howling Club Penguin Connector is an abandoned Ruby Project
 Written by:
 psudocky on GitHub
=end

require 'socket'

require 'digest'


class Howling
	def initialize(addr, service,showops)

		@addr = addr

		@service = service

		@showops = showops
		@sock = TCPSocket.new @addr, @service

	end


	# cryptographic functions

	# club penguin uses a weird hashing technique


	def cpencode(password)
	
		hash = Digest::MD5.hexdigest(password)

		swap = hash[16, 16] + hash[0, 16]


		return swap
	end



	def gethash(password, rndk)

		return cpencode(cpencode(password).upcase + rndk + "a1ebe00441f5aecb185d0ec178ca2305Y(02.>'H}t\":E1_root")

	end

	

	def recv
		begin
			while buf = @sock.sysread(4096)
				return buf
			end
		rescue
			print
		end

	end
	


	def keyret(buf) # return key to server
		
		buf =~ /<k>(.*)<\/k>/; $1
	
		return $1

	end
	

	def login(user, pass, rkey)

		@user = user

		@pass = pass

		@rkey = rkey

		@p = gethash(@pass, @rkey)
		@sock.write('<msg t="sys"><body action="login" r="0"><login z="w1"><nick><![CDATA['+@user+']]></nick><pword><![CDATA['+@p+']]></pword></login></body></msg>' + 0.chr)

	end
	

	def handshake(user, pass, apirev=153) # 153 should be compliant

		while baf = self.recv

			if baf.include? "policy" #handshake at correct time

				if @showops
					puts "[+] Handshaking server."

				end
				@sock.write('<msg t="sys"><body action="verChk" r="0"><ver v="153"/></body></msg>' + 0.chr)

			end

			if baf.include? "apiOK"

				if @showops
					puts "[+] API returned 'apiOK' response."

					puts "[+] Sending rndK request."

				end
				@sock.write('<msg t="sys"><body action="rndK" r="-1"></body></msg>' + 0.chr)

			elsif baf.include? "apiKO"

				if @showops
					puts "[-] API returned 'apiKO' response."
				end
				return false

				break

			end

			if baf.include? "rndK"

				if @showops
					puts "[+] Key sent to client, returning."
					puts "[+] Key: #{self.keyret(baf)}"

				end
				key = self.keyret(baf)

				@sock.write(key + 0.chr)

				self.login(user, pass, key)

			end

			if baf.include? "%l"

				if @showops
					puts "[+] Logged in to login server."
				end
				return baf.to_s
			
end
		
		end
	end

end
