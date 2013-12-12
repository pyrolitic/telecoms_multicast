#!/usr/bin/python3.2
import socket #networking
import struct #low level packing
import hashlib #sha256
import os #file and dir handling
import math, time #time_print
from PIL import Image #thumbnailering


def time_print(message):
	now = time.gmtime()
	epoch = time.time()
	print("%s:%s:%s:%s %s" % (now.tm_hour, now.tm_min, now.tm_sec, str(epoch - math.floor(epoch))[2:4], message))
	

#packet types
PACKET_TYPE_META = 0 #file meta data advertisement
PACKET_TYPE_CHUNK = 1 #file content chunk
PACKET_TYPE_NO_MORE = 2 #this peer won't deliver any more of this file
PACKET_TYPE_REQUEST = 3 #ask for a chunk
#PACKET_TYPE_HASH_RESOLVE = 4 #given a content hash, get the file name #not needed?


#codec objects for the different types of packets. all types are unsigned

#file meta data, sent as an advertisement of available files. type must be PACKET_TYPE_META
#type (1 byte), content length (8 bytes), content hash (32 bytes), file type (1 byte), thumbnail width (1 byte), 
#thumbnail height (1 byte), file name length (2 bytes), file name (encoded separately), thumbnail data (encoded separately)
file_meta_struct = struct.Struct(">Q32pBBBH")

#file content chunk, sent on request. type must be PACKET_TYPE_CHUNK or PACKET_TYPE_NO_MORE
#type (1 byte), file content hash (32 bytes), chunk id (4 bytes), chunck length (2 bytes), data (separate)
file_chunk_struct = struct.Struct(">32pIH")

#chunk request, meta data must be known. type must be PACKET_TYPE_REQUEST
#type (1 byte), file content hash (32 bytes), chunk index (4 bytes)
file_request_struct = struct.Struct(">32pI")

#not needed any more?
#hash to name resolution request. this will be answered by an advertisement. type must be PACKET_TYPE_HASH_RESOLVE
#type (1 byte), file content hash (32 bytes)
#hash_resolution_struct = struct.Struct(">B32p")



MULTICAST_GROUP = '235.3.13.37'
MULTICAST_PORT = 5009

FILE_TYPE_IMAGE = 0
FILE_TYPE_VIDEO = 1
FILE_TYPE_OTHER = 2

THUMBNAIL_HIGHEST = 90 #if aspect ratio is not 1:1, this is the maximum the longer side can be
FILE_CHUNK_SIZE = 65535 - 8 - 20 - 1 - file_chunk_struct.size #2^16, udp header, ip header, packet type, hash and stuff


#handle for files that are sent through the network, whether they have originated locally or are on a remote peer, or in between the two (parts of them are present, parts are missing)
#files a split into chunks as large as possible in a UDP packet (see FILE_CHUNK_SIZE)
class servable_file:
	def __init__(self, type, name, size, path=None, chunks=None, hash=None, thumb=None): #opening a local files must include the chunks, while a remote file will have the hash and thumbnail
		if not ((path and chunks) and not(hash and thumb) or not (path and chunks) and (hash and thumb)):
			raise Exception #TODO: better errors
	
		self.type = type
		self.name = name
		self.hash = hash
		self.size = size
		self.thumb = thumb
		
		self.path = path
		self.complete = False #whether all the chunks are present
		
		if chunks:
			self.complete = True #all the data is present
			self.chunks = chunks
			self.hash = self.compute_hash() #the hash was None
			self.make_thumb() #all the data is present, so 
			
		
		else:
			chunk_amount = size / FILE_CHUNK_SIZE
			if size % FILE_CHUNK_SIZE > 0: chunk_amount += 1
			self.chunks = [None for i in range(chunkAmount)] #array filled with Nones for all the chunks that will be requested from the network
			
			
	#@<name>(hash): <message>, for a common template
	def message(self, str):
		time_print("@" + self.name + hex(self.hash) + ": " + str)
			
			
	#chunk was downloaded, so add it to the list
	def add_chunk(self, chunk_id, chunk):
		if not self.complete:
			if chunks_id >= 0 and chunk_id < len(self.chunks):
				if self.chunks[chunk_id] is None:
					self.chunks[chunk_id] = chunk
					if all(self.chunks): #every chunk is not None
						self.complete = True
					
				else:
					if self.chunks[chunks_id] == chunk:
						self.message("warning: trying to replace chunk " + str(chunk_id) + " with the same data")
					
					else:
						self.message("warning: trying to replace chunk " + str(chunk_id) + " with different data")
						
			else:
				self.message("warning: chunk id " + str(chunk_id) + " out of range")
		
		else:
			self.message("trying to add chunk to already complete file")
		
	
	#sha 256 hash of the contents of the file, if all the chunks are present
	def compute_hash(self):
		if self.complete:
			hash_ob = hashlib.sha256()
			for chunk in self.chunks:
				hash_ob.update(chunk)
			
			return hash_ob.digest()
		
		else:
			self.message('warning: trying to compute the hash of an incomplete file')
			raise Exception

	
	#create a thumbnail for the file	
	def make_thumb(self):
		if self.complete:
			if not self.thumb:
				if self.type == FILE_TYPE_IMAGE:
					self.thumb = Image.open(self.path)
					#aspect ratio is preserved, so either width or height will be lower than THUMBNAIL_HIGHEST
					self.thumb.thumnail((THUMBNAIL_HIGHEST, THUMBNAIL_HIGHEST), PIL.Image.ANTIALIAS)
					
			else:
				self.message('warning: trying to create a thumbnail that already exists')
	
	
	#write the received file on to the disk			
	def write_file(self, dest_dir):
		if self.complete:
			#add up the size of all the chunks and compare them to the size that we got from the peer
			content_got_size = 0
			for chunk in self.chunks:
				content_got_size += len(chunk)

			if content_got_size == self.size:
				#get the hash of the actual content received and compare it to the hash that we got from the peer
				content_got_hash = compute_hash()

				if content_got_hash == self.hash:
					self.path = dest_dir + '/' + self.name
					try:
						handle = open(self.path, 'wb')

						for chunk in self.chunks:
							handle.write(chunk)

						handle.close()
						self.message("wrote downloaded file " + self.name)

					except Exception as e:
						self.message("error: could not write data to path " + self.path)
						raise e

				else:
					self.message("error: hash of content(" + hex(content_got_hash) + "does not match the given hash")

			else:
				self.message("error: size of content of does not match the given size")


#another peer in the network
class other:
	def __init__(self):
		self.files = [] #hashes

	def file_advert(self, content_hash, name, size, type):
		if content_hash not in self.files:
			self.files.append(content_hash)

#self
class peer:
	def __init__(self, group_ip, multicast_port):
		self.group_ip = group_ip
		self.multicast_port = multicast_port

		self.multicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) #udp datagram over ip
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) #one hop only, which limits it to the local network
		self.multicast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #http://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
		self.multicast_sock.bind(('', self.multicast_port)) #listen on any interface

		#subscribe to the multicast group, receiving on any interface
		mreq = struct.pack("4sl", socket.inet_aton(self.group_ip), socket.INADDR_ANY)
		self.multicast_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
		
		self.unicast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) #also create a socket that's used for one-to-one sending
	
		self.files = dict() #hash string => servable_file object
		self.files_to_send = [] #which files are to be sent (TODO: only once?)
		self.files_to_get = [] #files with missing chunks and will be requested
		
	def add_local_file(self, path):
		file_stat = None
		try:
			file_stat = os.stat(path) #raises exception if file does not exist
		except Exception as e:
			time_print('trying to add nonexisting file \'' + path + '\'')
			return
			
		file_size = file_stat.st_size
		
		#substring after either the last / or the last \ (if either exists)
		name = path.split('/')[-1].split('\\')[-1]
	
		if file_size == 0: #no use, it's empty
			time_print("file " + path + "has no contents")
		
		else:
			try:
				#TODO: deduce type of file
				file_type = FILE_TYPE_OTHER
			
				#load all the cunks
				chunks = []
				handle = open(path, 'rb') #raises exception if it can't be opened this way
				while True:
					chunk = handle.read(FILE_CHUNK_SIZE)
					if not chunk: break
					chunks.append(chunk)
				
				handle.close()
				f = servable_file(file_type, name, file_size, path=path, chunks=chunks)
				
				if f.hash in self.files.keys():
					time_print("trying to add already stored(in memory) file")
	
				else:
					time_print("added file '" + name + "', {" + f.hash.encode('hex') + "}")
					self.files[f.hash] = f
					self.files_to_send.append(f)
	
			except IOError as e:
				time_print('can\'t open file \'' + path + '\' for reading')
				raise e
		
	#let everyone in the network know of our presence, and what we'll serve
	def send_advertisements(self):
		print ('sending advertisements for every file')
	
		for serv_path in self.files:
			serv = self.files[serv_path]
			data = struct.pack('>B', PACKET_TYPE_META)
			data += file_meta_struct.pack(serv.size, serv.hash, serv.type, serv.thumb.size[0], serv.thumb.size[1], len(serv.name))
			data += serv.name.encode("utf8")
			data += serv.thumb.tostring()
			
			#send it to everyone
			self.multicast_sock.sendto(data, (self.group_ip, self.multicast_port))


if __name__ == '__main__':
	#the program is being invoked directly (rather than being imported as library)
	import sys
	if len(sys.argv) == 2:
		uploads_dir = sys.argv[1]
		
		peer = peer(MULTICAST_GROUP, MULTICAST_PORT)
		others = dict() #ip string => other object
		
		#gather all the files that can be served
		for f in os.listdir(uploads_dir):
			if os.path.isfile(f):
				peer.add_local_file(f)
				
		#peer.send_advertisements()
		
		
		#TODO: maybe object orient this whole block, maybe into peer
		while True:
			data, addr = peer.multicast_sock.recvfrom(65535)
			type = struct.unpack('>B', data[0])
			
			if type == PACKET_TYPE_META:
				try:
					size, hash, type, thumb_w, thumb_h, name_len = file_meta_struct.unpack(data[1:])
					name = data[1 + file_meta_struct.size : 1 + file_meta_struct.size + name_len].decode('utf8')
					thumb_data = data[1 + file_meta_struct.size + name_len :]
					thumb = Image.fromstring(thumb_data)
					
				except Exception as e:
					time_print("failed to unpack packet: " + e.message)
				
				if hash in peer.files:
					peer.files[hash].update_info(type, hash, name, thumb)
				
				else:
					f = servable_file(type, name, size, hash=hash, thumb=thumb)
					
			
			elif type == PACKET_TYPE_CHUNK:
				try:
					hash, chunk_id, chunk_len = file_chunk_struct.unpack(data[1:])
					chunk = data[1 + file_chunk_struct :]
					assert len(chunk) == chunk_len
					
				except Exception as e:
					time_print("failed to unpack packet: " + e.message)
					
				if hash in peer.files:
					#only keep chunks of files we know of
					peer.files[hash].add_chunk(chunk_id, chunk)
				
			
			elif type == PACKET_TYPE_NO_MORE:
				time_print("no more packet from " + addr)
			
			
			elif type == PACKET_TYPE_REQUEST:
				try:
					hash, chunk_id = file_request_struct.unpack(data[1:])
				
				except Exception as e:
					time_print("failed to unpack packet: " + e.message)
				
				if hash in peer.files:
					#see if we have the chunk in question and send it
					f = peer.files[hash]
					if chunk_id < len(f.chunks):
						if f.chunks[chunk_id] is not None:
							packet = str(PACKET_TYPE_CHUNK)
							packet += file_chunk_struct.pack(hash, chunk_id, f.chunks[chunk_id])
							peer.multicast_sock.sendto(packet, (peer.group_ip, peer.multicast_port))
				
			
			else:
				time_print("received packet with invalid type")
				
				
			#if there are any imcomplete files, send requests
			for incomplete in peer.files_to_get:
				for chunk_id in range(len(incomplete.chunks)):
					if incomplete.chunks[chunk_id] is None:
						packet = str(PACKET_TYPE_REQUEST)
						packet += file_request_struct(incomplete.hash, chunk_id)
						break #only send a request for the first missing chunk; TODO: is it too much traffic to not have this?
			
			#TODO: if there are any files added, send them anyway, once only (rather than the advertisement system)
			
			
			
	
	else:
		print("usage: " + sys.argv[0] + " <uploads dir>")

