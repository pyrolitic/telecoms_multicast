#!/usr/bin/python3.2

#libraries
import socket #IP networking
import os #file and dir handling
import time #constant.time_print, thread sleeping
from PIL import Image #thumbnailering
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
#instances of these objects sould be globally unique (one for each peer), so that when a peer is missed, the self.missing flag will be set, and the OutgoingFile code will remove it from its list of recipients
class OtherPeer:
	def __init__(self, nick):
		self.nick = nick
		self.last_presence = time.time() #now
		self.missing = False

class BadPacketException(Exception):
	def __init__(self, source, exception=None):
		self.source = source
		self.reason = exception.message if exception else ''
		Exception.__init__(self, "received packet that could not be decoded")

#peer running on this computer; there should only be one instance of this
class Peer(threading.Thread):
	def __init__(self, nickname):
		threading.Thread.__init__(self)
		self.nick = nickname
	
		self.multicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) #udp datagram over ip
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) #one hop only, which limits it to the local network
		self.multicast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #http://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
		self.multicast_sock.setblocking(0) #will now throw an error if recv() doesn't have anything to show
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
		self.multicast_sock.bind(('', constant.MULTICAST_PORT)) #listen on any interface

		#subscribe to the multicast group, receiving on any interface
		mreq = struct.pack("4sl", socket.inet_aton(constant.MULTICAST_GROUP), socket.INADDR_ANY)
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
		
		self.unicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) #also create a socket that's used for one-to-one sending
		self.unicast_sock.setblocking(0) #same as the other socket
	
		self.outgoing = dict() #hash(string) => files being sent and/or still alive (OutgoingFile)
		self.incoming = dict() #hash(sintrg) => files being received and/or still alive (IncomingFile)
		
		self.presence_last_sent = None #when the last presence packet was sent
		
		#threading, synchronization
		self.running = False
		self.activity_lock = threading.Lock()
		
		self.others = dict() #address(string) => OtherPeer
		
		self.send_presence() #if nothing above threw an error, we can sefaly say we're present in the network
		

	def add_file_to_send(self, path, time_to_live):
		file_stat = None
		try:
			file_stat = os.stat(path) #raises exception if file does not exist
			
		except Exception as e:
			constant.time_print('trying to add nonexisting file \'' + path + '\'')
			return
			
		file_size = file_stat.st_size
		
		#substring after either the last / or the last \ (if either exists)
		name = path.split('/')[-1].split('\\')[-1]
	
		if file_size == 0: #no use, it's empty
			constant.time_print("file " + path + "has no contents")
		
		else:
			try:
				#deduce type of file
				file_type = constant.FILE_TYPE_OTHER
				
				dotted = name.split('.')
				if len(dotted) > 1:
					#there is at least one dot, so assume the last substring corresponds to the file type
					suffix = dotted[-1].lower() #make lowercase
					
					#TODO: terrible system; should use header inspection instead like the linux "file" command
					if suffix in ('jpg', 'jpeg', 'png', 'gif', 'tga', 'bmp', 'tiff'): file_type = constant.FILE_TYPE_IMAGE
					elif suffix in ('mp3', 'wav', 'ogg', 'aac'): file_type = constant.FILE_TYPE_AUDIO
					elif suffix in ('mp4', 'avi', 'webm'): file_type = constant.FILE_TYPE_VIDEO
				
				
				self.activity_lock.acquire() #self.others and OutgoingFile existance and state must be atomic relative to threading
				
				recipients = self.others.copy() #clone of recipients, at this time #TODO: ensure that others with .missing set are not present at this point in time
				f = OutgoingFile(file_type, name, file_size, path, time_to_live, recipients)
				
				if f.hash in self.outgoing.keys():
					constant.time_print("trying to add already stored(in memory) file")
	
				else:
					constant.time_print("added " + constant.FILE_TYPE_NAMES[file_type] + " file '" + name + "', {" + f.hash.encode('hex') + "}")
					self.outgoing[f.hash] = f
					
				self.activity_lock.release()
	
			except IOError as e:
				constant.time_print('can\'t open file \'' + path + '\' for reading')
				raise e
				
				
	def send_presence(self):
		#constant.time_print("sent presence packet")
		data = packet.make_presence_packet(self.nick)
		self.multicast_sock.sendto(data, (constant.MULTICAST_GROUP, constant.MULTICAST_PORT))
		self.presence_last_sent = time.time()
		

	#this will listen continuously for incoming packets and handle/reply to them
	def run(self): 
		self.running = True
	
		while self.running:
			self.activity_lock.acquire() #keep all state changes atomic with respect to threads
		
			now = time.time()
		
			#are we missing anyone?
			gone = []
			for addr in self.others:
				other = self.others[addr]
				if now - other.last_presence > constant.TIME_TO_MISSING:
					other.missing = True
					gone.appen(other)
				
			for left in gone:
				constant.time_print(self.others[left].name + "(" + left + ") left")
				self.others.remove(left)
	

			if now - self.presence_last_sent > constant.PRESENCE_INTERVAL:
				#we're still here
				self.send_presence()
		
			'''
			#process acknowledgements first, which are received on the unicast socket
			while True: #handle every ack packet in the queue
				try:
					data, (addr, _) = self.unicast_sock.recvfrom(constant.UDP_PACKET_SIZE)
					packet_type = ord(data[0])
					
					constant.time_print("received packet with type " + str(packet_type))
				
					if packet_type in (packet.PACKET_TYPE_ACK_META, packet.PACKET_TYPE_ACK_CHUNK, packet.PACKET_TYPE_ACK_DELETE):
						try:
							file_hash, chunk_id = packet.ack_struct.unpack(data[1:])
						
						except Exception as e:
							raise BadPacketException(addr, e)
						
						if file_hash in self.outgoing:
							f = self.files[file_hash]
							f.got_ack(addr, packet_type, chunk_id)
							if f.deleted:
								constant.time_print("successfully delivered file " + f.name)
								self.outgoing.remove(f)
					
					else:
						raise BadPacketException(addr)
							
							
				except socket.error:
					#no packet in the queue, sleep for a bit
					#constant.time_print("no more unicast packets")
					time.sleep(0.01) #10 milliseconds
					break
					
				except BadPacketException as e:
					constant.time_print("bad packet from " + e.source)
			'''
	
			#then handle the multicast packets
			while True: #handle every packet in the queue
				try:
					data, (addr, _) = self.multicast_sock.recvfrom(constant.UDP_PACKET_SIZE) #the function returns (data, (addr, port)), but port is not needed
					packet_type = ord(data[0])
					
					constant.time_print("received packet with type " + str(packet_type))
					
					
					#acknowledgements
					if packet_type in (packet.PACKET_TYPE_ACK_META, packet.PACKET_TYPE_ACK_CHUNK, packet.PACKET_TYPE_ACK_DELETE):
						try:
							file_hash, chunk_id = packet.ack_struct.unpack(data[1:])
						
						except Exception as e:
							raise BadPacketException(addr, e)
						
						if file_hash in self.outgoing:
							f = self.files[file_hash]
							f.got_ack(addr, packet_type, chunk_id)
							if f.deleted:
								constant.time_print("successfully delivered file " + f.name)
								self.outgoing.remove(f)
								

					#this peer (still) exists
					elif packet_type == packet.PACKET_TYPE_PRESENCE:
						constant.time_print("presence packet from " + addr)
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
							self.others[addr] = OtherPeer(nick)
		
		
					#this peer wants to send us a new file
					elif packet_type == packet.PACKET_TYPE_META:
						constant.time_print("meta packet from " + addr)
						try:
							file_size, file_hash, file_type, thumb_w, thumb_h, time_to_live, file_name_len = packet.meta_struct.unpack(data[1 : packet.meta_struct.size + 1])
							file_name = data[1 + packet.meta_struct.size : 1 + packet.meta_struct.size + file_name_len].decode('utf8')
							thumb_data = data[1 + packet.meta_struct.size + file_name_len :]
							thumb = Image.fromstring(thumb_data, (thumb_w, thumb_h))
			
						except Exception as e:
							raise BadPacketException(addr, e)
		
						#add it to the list
						if file_hash not in self.incoming:
							self.incoming[file_hash] = IncomingFile(file_type, file_name, file_size, file_hash, time_to_live, thumb)
			
						#send a unicast acknowledgement
						ack = packet.make_ack_packet(file_hash)
						self.unicast_sock.sendto(ack, (addr, constant.MULTICAST_PORT))
			
	
					#this peer is giving us another piece of some file
					elif packet_type == packet.PACKET_TYPE_CHUNK:
						constant.time_print("chunk packet from " + addr)
						try:
							file_hash, chunk_id, chunk_len = packet.chunk_struct.unpack(data[1 : packet.chunk_struct.size + 1])
							chunk = data[1 + packet.chunk_struct :]
							assert len(chunk) == chunk_len
			
						except Exception as e:
							raise BadPacketException(addr, e)
			
						if file_hash in self.files:
							#only keep chunks of files we know of
							self.incoming[file_hash].add_chunk(chunk_id, chunk)
				
							#send a unicast acknowledgement
							ack = packet.make_ack_packet(file_hash, chunk_id)
							self.unicast_sock.sendto(ack, (addr, constant.MULTICAST_PORT))
		
	
					#this peer  wants us not to have the file anymore
					elif packet_type == packet.PACKET_TYPE_DELETE:
						constant.time_print("delete packet from " + addr)
						try:
							file_hash = packet.delete_struct.unpack(data[1:])[0]
						
						except Exception as e:
							raise BadPacketException(addr, e)
					
						#there's no point in keeping the file if it's not complete, and if it is complete, be nice, delete it
						if file_hash in self.incoming:
							f = self.incoming[file_hash]
							self.incoming.remove(file_hash)
						
						#send ack whether we had file or not, since it could be the case that before we got the metadata, 
						#the sender wants to delete the file early; also it could be that our first ack was dropped
						ack = packet.make_ack_packet(file_hash, packet.PACKET_TYPE_ACK_DELETE)
						self.unicast_sock.sendto(ack, (addr, constant.MULTICAST_PORT))


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
			for outgoing in self.outgoing.values():
				data = outgoing.next_packet()
				if data is not None: self.multicast_sock.sendto(data, (self.group_ip, self.multicast_port))
			
		
			#see if we need to delete any incoming file
			deleting = []
			for incoming in self.incoming.values():
				if incoming.completed:
					if now - incoming.completed_at > incoming.ttl:
						deleting.push(incoming.hash)
						
			for file_hash in deleting:
				f = self.incoming[file_hash]
				constant.time_print("deleting file " + f.name)
				self.incoming.remove(file_hash)
					
				
			self.activity_lock.release() #keep all state changes atomic with respect to threads
			time.sleep(0.01) #TODO I think this is needed to allow the other thread to acquire the lock, but I might be wrong
					
	def kill(self):
		self.activity_lock.acquire()
		self.running = False
		self.activity_lock.release()


#runs on ^C
def signal_handler(signal, frame):
	print("hard shutdown")
	os._exit(1)


if __name__ == '__main__':
	#the module is being invoked directly (rather than being imported as a library)
	
	signal.signal(signal.SIGINT, signal_handler) #*nix
	#signal.signal(signal.CTRL_C_EVENT, signal_handler) #windoze
	
	if len(sys.argv) == 2:
		donwloads_dir = sys.argv[1]
		
		peer = Peer('blank')
		peer.start() #spawn network thread
		
		#basic console
		while True: 
			try:
				line = raw_input('>')
			
				tokens = line.split(' ')
				command = tokens[0].lower()
				
				if command == 'kill':
					peer.kill()
					print("goodbye")
					break
					
				elif command == 'peers':
					if len(peer.others) > 0:
						for addr in peer.others:
							print(" " + peer.others[addr].nick + "(" + addr + ")")
							
					else:
						print("all alone")
					
				elif command == 'nick':
					nick = tokens[1]
					peer.nick = nick
				
				elif command == 'send':
					path = tokens[1]
					ttl = int(tokens[2])
					peer.add_file_to_send(path)
					
				elif command == 'help':
					print("kill - end the progrma")
					print("peers - list known peers")
					print("nick <name> - change own nickname")
					print("send <path> <ttl in seconds> - send a file to all known peers")
					
				else: raise Exception()
			
			except Exception as e:
				print('badly formed command; ' + e.message)
				pass
	
	else:
		print("usage: " + sys.argv[0] + " <downloads dir>")

