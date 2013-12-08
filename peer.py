#!/usr/bin/python3.2
import socket, struct, hashlib, os

MULTICAST_GROUP = '235.3.13.37'
MULTICAST_PORT = 5009

FILE_TYPE_IMAGE = 0
FILE_TYPE_VIDEO = 1

class servable_file:
	def __init__(self, path):
		file_stat = os.stat(path) #raises exception if file does not exist
		self.size = file_stat.st_size
		
		if self.size == 0: #no use it's empty
			raise ValueError #TODO: make a better exception class
	
		self.name = path.split('/')[-1]
		self.handle = open(path, 'rb') #raises exception if it can't be opened this way
		
		#determine the file type
		self.type = FILE_TYPE_IMAGE #TODO
		
		#get the hash
		hash_ob = hashlib.sha256()
		while True:
			block = self.handle.read(8192)
			if not block: break;
			hash_ob.update(block)
		
		self.hash = hash_ob.digest()
		
		print('added file ' + self.name + ', of size ' + str(self.size) + ', with content hash ' + str(self.hash).encode('hex'))
		
		#if type == FILE_TYPE_IMAGE:
		#	pass #maybe use PIL to make a thumbnail
			
			
	def close(self):
		self.handle.close()
			

#requestable file
class other_file:
	def __init__(self, name, size, type):
		self.name = name
		self.size = size
		self.type = type


#another peer in the network
class other: 
	def __init__(self):
		self.files = dict()
		
	def file_advert(self, content_hash, name, size, type):
		if content_hash not in self.files:
			self.files[content_hash] = other_file(name, size, type)

#self
class peer:
	def __init__(self, group_ip, multicast_port):
		self.group_ip = group_ip
		self.multicast_port = multicast_port
	
		self.multicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) #udp datagram over ip
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) #one hop only, which limits it to the local network
		self.multicast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #http://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t

		self.multicast_sock.bind(('', self.multicast_port)) #listen on interface

		#subscribe to the multicast group, receiving on any interface
		mreq = struct.pack("4sl", socket.inet_aton(self.group_ip), socket.INADDR_ANY)
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
		
		self.unicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) #also create a socket that's used for one-to-one sending
	
		self.files = dict() #hash string => servable_file object
		
	def add_file(self, path):
		try:
			f = servable_file(path)
			if f.hash in self.files:
				f.close() #already there
		
			else:
				self.files[f.hash] = f
		
		except:
			pass
		
	#let everyone in the network know of our presence, and what we'll serve
	def send_advertisements(self):
		for serv_path in self.files:
			serv = self.files[serv_path]
			data = file_meta_struct.pack(PACKET_TYPE_META, serv.size, serv.hash, serv.type, len(serv.name))
			data += serv.name.encode("utf8")
			
			#send it to everyone
			self.multicast_sock.sendto(data, (self.group_ip, self.multicast_port))
		
'''
file_pa = sys.argv[1]
try:
		
'''

#codec objects for the different types of packets. all types are unsigned

#packet types
PACKET_TYPE_META = 0 #file meta data advertisement
PACKET_TYPE_CHUNK = 1 #file content chunk
PACKET_TYPE_NO_MORE = 2 #this peer won't deliver any more of this file
PACKET_TYPE_REQUEST = 3 #ask for a chunk
PACKET_TYPE_HASH_RESOLVE = 4 #given a content hash, get the file name

#file meta data, sent as an advertisement of available files
#type (1 byte), content length (8 bytes), content hash (32 bytes), file type (1 byte), file name length (2 bytes), file name (encoded separately)
#type must be PACKET_TYPE_META
file_meta_struct = struct.Struct(">BQ32pBH")

#file content chunk, sent on request
#type (1 byte), file content hash (32 bytes), first byte index (8 bytes), chunck length (2 bytes), data (separate)
#type must be PACKET_TYPE_CHUNK or PACKET_TYPE_NO_MORE
file_chunk_strut = struct.Struct(">B32pQH")

#chunk request, meta data must be known
#type (1 byte), file content hash (32 bytes), first byte index (8 bytes)
#type must be PACKET_TYPE_REQUEST
file_request_struct = struct.Struct(">B32pQ")

#hash to name resolution request. this will be answered by an advertisement
#type (1 byte), file content hash (32 bytes)
hash_resolution_struct = struct.Struct(">B32p")

if __name__ == '__main__':
	#the program is being invoked directly (rather than being imported as library)
	import sys
	if len(sys.argv) == 2:
		data_dir = sys.argv[1]
		
		peer = peer(MULTICAST_GROUP, MULTICAST_PORT)
		others = dict() #ip string => other
		
		#gather all the files that can be served
		for f in os.listdir(data_dir):
			if os.path.isfile(f):
				peer.add_file(f)
				
		peer.send_advertisements()
	
	else:
		print("usage: " + sys.argv[0] + " <data dir>")

