#!/usr/bin/python3.2

#libraries
import socket #IP networking
import os #file and dir handling
import time #constant.time_print, thread sleeping
from PIL import Image #thumbnailing
import struct #binary packing and unpacking
import threading #threading, synchronization

import sys #command line arguments
import signal #hard exit on ^C

#own files
from outgoing_file import OutgoingFile
from incoming_file import IncomingFile
import constant
import packet

#another peer in the network
#instances of these objects should be globally unique (one for each peer), so that when a peer is missed, the self.missing flag will be set, and the OutgoingFile code will remove it from its list of recipients
class OtherPeer:
	def __init__(self, nick):
		self.nick = nick
		self.last_presence = time.time() #now
		self.missing = False #whether it has timed out
		

class BadPacketException(Exception):
	def __init__(self, source, exception=None):
		self.source = source
		self.reason = exception.message if exception else ''
		Exception.__init__(self, "received packet that could not be decoded")

#peer running on this computer; there should only be one instance of this
class Peer(threading.Thread):
	def __init__(self, download_dir, nickname):
		threading.Thread.__init__(self)
		self.downloads_dir = download_dir
		self.nick = nickname
	
		self.multicast_sock = None
		self.unicast_sock = None
	
		self.outgoing = dict() #hash(string) => files being sent and/or still alive (OutgoingFile)
		self.incoming = dict() #hash(string) => files being received and/or still alive (IncomingFile)
		
		self.presence_last_sent = None #when the last presence packet was sent
		
		#threading, synchronization
		self.running = False
		self.activity_lock = threading.Lock()
		
		self.others = dict() #address(string) => OtherPeer
		
		self.init_socket() #"connect" to the network
		self.send_presence() #if nothing above threw an error, we can safely say we're present in the network
		
		
	def init_socket(self):
		self.multicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) #udp datagram over ip
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) #one hop only, which limits it to the local network
		self.multicast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #http://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
		self.multicast_sock.setblocking(0) #will now raise socket.error if .recvfrom() doesn't have anything to show
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
		self.multicast_sock.bind(('', constant.MULTICAST_PORT)) #listen on any interface

		#subscribe to the multicast group, receiving on any interface
		mreq = struct.pack("4sl", socket.inet_aton(constant.MULTICAST_GROUP), socket.INADDR_ANY)
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
		
		self.unicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) #also create a socket that's used for one-to-one sending
		self.unicast_sock.setblocking(0) #same as the other socket
		

	def add_file_to_send(self, path, time_to_live):
		file_stat = None
		try:
			file_stat = os.stat(path) #raises exception if file does not exist
			
		except Exception as e:
			constant.time_print('trying to add non-existing file \'' + path + '\'')
			return
			
		file_size = file_stat.st_size
		
		#substring after either the last / or the last \ (if either exists)
		name = path.split('/')[-1].split('\\')[-1]
	
		if file_size == 0: #no use, it's empty
			constant.time_print("file " + path + "has no contents")
		
		else:
			try:
				#deduce type of file
				file_type = constant.FILE_TYPE_OTHER #unknown type or no suffix present
				
				dotted = name.split('.')
				if len(dotted) > 1:
					#there is at least one dot, so assume the last substring corresponds to the file type
					suffix = dotted[-1].lower() #make lowercase
					
					#TODO: terrible system; should use header inspection instead like the unix "file" command
					if suffix in ('jpg', 'jpeg', 'png', 'gif', 'tga', 'bmp', 'tiff'): file_type = constant.FILE_TYPE_IMAGE
					elif suffix in ('mp3', 'wav', 'ogg', 'aac'): file_type = constant.FILE_TYPE_AUDIO
					elif suffix in ('mp4', 'avi', 'webm'): file_type = constant.FILE_TYPE_VIDEO
				
				
				with self.activity_lock: #locks the mutex for the duration of the block, to ensure existence of files is atomic
					recipients = self.others.copy() #clone of recipients, at this time #TODO: ensure that others with .missing set are not present at this point in time
					f = OutgoingFile(file_type, name, file_size, path, time_to_live, recipients)
					
					if f.hash in self.outgoing.keys():
						constant.time_print("trying to add already stored(in memory) file")
		
					else:
						constant.time_print("added " + constant.FILE_TYPE_NAMES[file_type] + " file '" + name + "', {" + f.hash.encode('hex') + "}")
						print("sending to:")
						for addr in recipients:
							print(recipients[addr].nick + "(" + addr + ")")
							
						self.outgoing[f.hash] = f
	
			except IOError as e:
				constant.time_print('can\'t open file \'' + path + '\' for reading')
				raise e
			
	def send_multicast(self, data):
		#nonblocking sending can fail if the sending buffer is full
		while True:
			try:
				self.multicast_sock.sendto(data, (constant.MULTICAST_GROUP, constant.MULTICAST_PORT))
				break
			
			except:
				constant.time_print("eagain multicast")
				time.sleep(0.1)
				#EAGAIN most likely

	def send_unicast(self, addr, data):
		#nonblocking sending can fail if the sending buffer is full
		while True:
			try:
				self.unicast_sock.sendto(data, (addr, constant.MULTICAST_PORT))
				break
			
			except:
				constant.time_print("eagain unicast")
				time.sleep(0.1)
				#EAGAIN most likely
				
	def send_presence(self):
		#constant.time_print("sent presence packet")
		data = packet.make_presence_packet(self.nick)
		self.send_multicast(data)
		self.presence_last_sent = time.time()
		

	#this will listen continuously for incoming packets and handle/reply to them
	def run(self): 
		self.running = True
	
		while self.running:
			with self.activity_lock: #keep all state changes atomic with respect to threads
			
				now = time.time()
			
				#are we missing anyone?
				gone = []
				for addr in self.others:
					other = self.others[addr]
					if now - other.last_presence > constant.TIME_TO_MISSING:
						other.missing = True
						gone.append(addr)
					
				for addr in gone:
					constant.time_print(self.others[addr].nick + "(" + addr + ") left")
					del self.others[addr]
		
	
				if now - self.presence_last_sent > constant.PRESENCE_INTERVAL:
					#we're still here
					self.send_presence()
		
				#process every packet in the queue first
				while True: #handle every packet in the queue
					try:
						data, (addr, _) = self.multicast_sock.recvfrom(constant.UDP_PACKET_SIZE) #the function returns (data, (addr, port)), but port is not needed
						packet_type = ord(data[0])
						
						nick = self.others[addr].nick if addr in self.others else ''
						constant.time_print("received " + packet.PACKET_TYPE_NAMES[packet_type] + " from " + nick + '(' + addr + ')')
						
						#acknowledgements
						if packet_type in (packet.PACKET_TYPE_ACK_META, packet.PACKET_TYPE_ACK_CHUNK, packet.PACKET_TYPE_ACK_DELETE):
							try:
								file_hash, chunk_id = packet.ack_struct.unpack(data[1:])
							
							except Exception as e:
								raise BadPacketException(addr, e)
							
							if file_hash in self.outgoing:
								f = self.outgoing[file_hash]
								f.got_ack(addr, packet_type, chunk_id)
								if f.deleted:
									constant.time_print("successfully delivered file " + f.name)
									del self.outgoing[file_hash]
							
							else:
								constant.time_print("received meta ack for file{" + file_hash.encode("hex") + "} we're not serving")
									
	
						#this peer (still) exists
						elif packet_type == packet.PACKET_TYPE_PRESENCE:
							try:
								nick_encoded_len = packet.presence_struct.unpack(data[1 : 1 + packet.presence_struct.size])[0] #[0] needed cause it's a one-tuple
								nick_encoded = data[1 + packet.presence_struct.size:]
								nick = nick_encoded.decode('utf8')
								assert nick_encoded_len == len(nick_encoded)
				
							except Exception as e:
								raise BadPacketException(addr, e)
				
							if addr in self.others:
								other = self.others[addr]
								other.last_presence = now
								
								if other.nick != nick:
									constant.time_print(other.nick + " is now known as " + nick)
									
								other.nick = nick
								other.missing = False #in case they were marked as missing above
				
							else:
								constant.time_print('welcome ' + nick + '(' + addr + ')')
								self.others[addr] = OtherPeer(nick)
			
			
						#this peer wants to send us a new file
						elif packet_type == packet.PACKET_TYPE_META:
							try:
								file_size, file_hash, file_type, thumb_w, thumb_h, file_name_len, time_to_live = packet.meta_struct.unpack(data[1 : packet.meta_struct.size + 1])
								file_name = data[1 + packet.meta_struct.size : 1 + packet.meta_struct.size + file_name_len].decode('utf8')
								thumb_data = data[1 + packet.meta_struct.size + file_name_len :]
								thumb = Image.fromstring('RGBA', (thumb_w, thumb_h), thumb_data)
				
							except Exception as e:
								raise BadPacketException(addr, e)
			
							#add it to the list
							if file_hash not in self.incoming:
								self.incoming[file_hash] = IncomingFile(file_type, file_name, file_size, file_hash, time_to_live, thumb)
								self.incoming[file_hash].message("new file")
				
							#send a unicast acknowledgement
							ack = packet.make_ack_packet(file_hash, packet.PACKET_TYPE_ACK_META)
							self.send_unicast(addr, ack)
				
		
						#this peer is giving us another piece of some file
						elif packet_type == packet.PACKET_TYPE_CHUNK:
							try:
								file_hash, chunk_id, chunk_len = packet.chunk_struct.unpack(data[1 : packet.chunk_struct.size + 1])
								chunk = data[packet.chunk_struct.size + 1 :]
								assert len(chunk) == chunk_len
				
							except Exception as e:
								raise BadPacketException(addr, e)
				
							if file_hash in self.incoming:
								#only keep chunks of files we know of
								self.incoming[file_hash].add_chunk(chunk_id, chunk)
					
								#send a unicast acknowledgement
								ack = packet.make_ack_packet(file_hash, packet.PACKET_TYPE_ACK_CHUNK, chunk_id)
								self.send_unicast(addr, ack)
			
		
						#this peer  wants us not to have the file anymore
						elif packet_type == packet.PACKET_TYPE_DELETE:
							try:
								file_hash = packet.delete_struct.unpack(data[1:])[0]
							
							except Exception as e:
								raise BadPacketException(addr, e)
						
							#there's no point in keeping the file if it's not complete, and if it is complete, be nice, delete it
							if file_hash in self.incoming:
								del self.incoming[file_hash]
							
							#send ack whether we had file or not, since it could be the case that before we got the metadata, 
							#the sender wants to delete the file early; also it could be that our first ack was dropped
							ack = packet.make_ack_packet(file_hash, packet.PACKET_TYPE_ACK_DELETE)
							self.send_unicast(addr, ack)
	

						else:
							raise BadPacketException(addr + " - wrong type") #TODO ugly hack
						
						
					except socket.error:
						#no packet in the queue, sleep for a bit
						#constant.time_print("no more multicast packets")
						time.sleep(0.01) #10 milliseconds
						break
						
					except BadPacketException as e:
						constant.time_print("bad packet from " + e.source + "; " + e.reason)
					
		
				#send the next packet of every outgoing file
				deleting = []
				for outgoing in self.outgoing.values():
					data = outgoing.next_packet()
					if data is not None:
						self.send_multicast(data)
					
					else:
						#the file has not packets to send right now, see if we should get rid the of it
						if not outgoing.deletion_request:
							if outgoing.content_sent and now - outgoing.content_sent_at > outgoing.ttl:
								#the last recipient should have deleted the file by now
								deleting.append(outgoing.hash)
									
						elif outgoing.deleted:
							#everyone acknowledged having deleted the file on our request
							deleting.append(outgoing.hash)
						
				for file_hash in deleting:
					del self.outgoing[file_hash]
				
			
				#see if we need to delete any incoming file
				deleting = []
				for incoming in self.incoming.values():
					if incoming.complete:
						if now - incoming.completed_at > incoming.ttl:
							deleting.append(incoming.hash)
							
						else:
							if not incoming.saved:
								incoming.message("successfully received all chunks; saving. we can have it for " + str(incoming.ttl) + " seconds")
								incoming.write_to_disk(self.downloads_dir)
							
				for file_hash in deleting:
					f = self.incoming[file_hash]
					f.message("deleting")
					os.remove(f.path)
					del self.incoming[file_hash]
					
						
			time.sleep(0.01) #TODO I think this is needed to allow the other thread to acquire the lock, but I might be wrong
					
	def kill(self):
		with self.activity_lock:
			self.running = False


#runs on ^C
def signal_handler(signal, frame):
	print("hard shutdown")
	os._exit(1) #supposedly pretty dangerous


if __name__ == '__main__':
	#the module is being invoked directly (rather than being imported as a library)
	
	signal.signal(signal.SIGINT, signal_handler) #*nix
	#signal.signal(signal.CTRL_C_EVENT, signal_handler) #windoze
	
	if len(sys.argv) == 2:
		downloads_dir = sys.argv[1]
		
		peer = Peer(downloads_dir, 'blank')
		peer.start() #spawn network thread
		
		#basic console. sadly it clashes with the debug output
		while True: 
			try:
				line = raw_input('>')
				if len(line) == 0: continue
			
				tokens = line.split(' ')
				command = tokens[0].lower()
				
				if command == 'kill':
					peer.kill()
					print("goodbye")
					break
					
				elif command == 'peers':
					if len(peer.others) > 0:
						for addr in peer.others:
							print("}" + peer.others[addr].nick + "(" + addr + ")")
							
					else:
						print("all alone")
					
				elif command == 'nick':
					nick = tokens[1]
					peer.nick = nick
				
				elif command == 'send':
					path = tokens[1]
					ttl = int(tokens[2])
					peer.add_file_to_send(path, ttl)
					
				elif command == 'help':
					print("kill - end the program")
					print("peers - list known peers")
					print("nick <name> - change own nickname")
					print("send <path> <ttl in seconds> - send a file to all known peers")
					
				else: raise Exception()
			
			except Exception as e:
				print('badly formed command; ' + e.message)
				pass
	
	else:
		print("usage: " + sys.argv[0] + " <downloads dir>")

