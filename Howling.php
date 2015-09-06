<?php
class Howling {
	function Howling($addr,$service,$showops){
		$this->addr = $addr;
		$this->service = $service;
		$this->showops = $showops;
		$this->sock = socket_create(AF_INET, SOCK_STREAM, 0);
		socket_connect($this->sock,$this->addr,$this->service);
	}

	// cryptographic functions

	// club penguin uses a weird hashing technique

	function cpencode($password){
		$hash = md5($password);
		$swap = substr($hash,16,32).substr($hash,0,16);
		return $swap;
	}
		
	function gethash($password,$rndk){
		return $this->cpencode(strtoupper($this->cpencode($password)).$rndk."a1ebe00441f5aecb185d0ec178ca2305Y(02.>'H}t\":E1_root");
	}

	function recv(){
		try{
			while($buf = socket_read ($this->sock,4096)){
				return $buf;
			}
		}catch(Exception $e){
			print("");
		}
	}
		
	function keyret($buf){
		preg_match('#\<k\>(.+)\<\/k\>#s',$buf,$i);
		return $i[1];
	}
		
	function login($user,$pass,$rkey){
		$this->user = $user;
		$this->pass = $pass;
		$this->rkey = $rkey;
		$this->p = $this->gethash($this->pass,$this->rkey);
		socket_write($this->sock,'<msg t="sys"><body action="login" r="0"><login z="w1"><nick><![CDATA['.$this->user.']]></nick><pword><![CDATA['.$this->p.']]></pword></login></body></msg>'.chr(0));
	}
		
	function handshake($user,$pass,$apirev=153){
		while($baf = $this->recv()){
			if(strpos($baf,'policy') !== false){
				if($this->showops){
					echo "[+] Handshaking server.\n";
				}
				socket_write($this->sock,'<msg t="sys"><body action="verChk" r="0"><ver v="'.$apirev.'"/></body></msg>'.chr(0));
			}
			if(strpos($baf,'apiOK') !== false){
				if($this->showops){
					echo "[+] API returned 'apiOK' response.\n";
					echo "[+] Sending rndK request.\n";
				}
				socket_write($this->sock,'<msg t="sys"><body action="rndK" r="-1"></body></msg>'.chr(0));
			} else if(strpos($baf,'apiKO') !== false){
				if($this->showops){
					echo "[-] API returned 'apiKO' response.\n";
				}
				return false;
			}
			if(strpos($baf,'rndK') !== false){
				$key = $this->keyret($baf);
				if($this->showops){
					echo "[+] Key sent to client, returning.\n";
					echo "[+] Key: ".$key."\n";
				}
				socket_write($this->sock,$key.chr(0));
				$this->login($user,$pass,$key);
			}
			if(strpos($baf,'%l') !== false){
				if($this->showops){
					echo "[+] Logged in to login server.\n";
				}
				return $baf;
			}
		}
	}
}
?>
