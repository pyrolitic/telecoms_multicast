#libraries
from PIL import Image #thumbnailing
import random #for picking recipients at random
import time

#own files
from proto_file import ProtoFile
import packet
import constant

#handle for files that are to be sent
class OutgoingFile(ProtoFile):
	#                   number,    string,    number,    string,   number,       dict of address(string) => OtherPeer (assumed to be a copy)
	def __init__(self, file_type, file_name, file_size, file_path, time_to_live, recipients):
		ProtoFile.__init__(self, file_type, file_name, file_size, time_to_live)
		self.path = file_path
		
		self.recipients = recipients #stays the same unless a recipient times out and is then left out
		
		self.meta_sent = False #whether every receiver has acknowledged the meta data
		self.content_sent = False #whether every receiver has acknowledged every chunk
		self.deleted = False #whether every recipient has acknowledged deleting the file
		
		self.meta_began_at = None #roundabouts when the transmission started
		self.content_began_at = None #when the first content packet was sent
		self.delete_request_began_at = None #when the user requested the early deletion
		self.content_sent_at = None #when the last content ack(in the sense of the last missing chunk having been ack'd) arrived at, marking the latest possible start of a lifetime of a copy of this file
		
		self.meta_acks = set()# recipient address(string) of peer that has not acknowledged the metadata packet
		self.content_acks = dict() #recipient address(string) of peer => array of unacknowledged packets, of length > 0
		self.delete_acks = set() #recipient (OtherPeer) that has not acknowledged the file deleted packet
		
		self.deletion_request = False #whether the time to live of the file has ended, or the user wants to delete it early
		
		
		for r in recipients:
			self.meta_acks.add(r)
			self.content_acks[r] = list(range(len(self.chunks))) #[0, 1, 2 .. len(chunks) - 1]; list is to make it work in both python 2 and 3
			self.delete_acks.add(r)
		
		
		#load contents
		try: self.handle = open(self.path, 'rb') #this one can throw an IOError
		except IOError as e: raise e
		
		for i in range(len(self.chunks)):
			chunk = self.handle.read(packet.FILE_CHUNK_SIZE)
			self.chunks[i] = chunk
		
		self.handle.close()
		
		#compute hash of content
		self.hash = self.compute_content_hash()
		
		#create a thumbnail, if applicable
		self.thumb = None
		
		if self.type == constant.FILE_TYPE_IMAGE:
			self.thumb = Image.open(self.path)
			#aspect ratio is preserved, so either width or height will be lower than THUMBNAIL_HIGHEST
			self.thumb.thumbnail((constant.THUMBNAIL_HIGHEST, constant.THUMBNAIL_HIGHEST), Image.ANTIALIAS)
			
			
	#return any packet that wasnt acknowledged
	#returns None in case there are no packets that this file wants to send right now (there is a gap between sending the file and sending the deletion requests)
	def next_packet(self):
		#first go through the recipients to see if any of them have gone missing since the transmission began
		gone = []
		for addr in self.recipients:
			r = self.recipients[addr]
			if r.missing:
				constant.time_print("lost recipient " + r.nick)
				if addr in self.meta_acks: 
					self.meta_acks.remove(addr)
					if len(self.meta_acks) == 0:
						self.message("the last peer we were waiting on to send to send us a meta ack has timed out")
						self.meta_send = True
					
				if addr in self.content_acks: 
					del self.content_acks[addr]
					if len(self.content_acks) == 0:
						self.message("the last peer we were waiting on to send to send us a content ack has timed out")
						self.content_sent = True
						self.content_sent_at = time.time()
					
				if addr in self.delete_acks: 
					self.delete_acks.remove(addr)
					if len(self.content_acks) == 0:
						self.message("the last peer we were waiting on to send to send us a delete ack has timed out")
						self.deleted = True
					
				gone.append(addr)
		
		for addr in gone:
			self.message("recipient" + addr + " timed out")
			self.recipients.remove(addr)
		
		data = None
		
		if self.deletion_request:
			if not self.deleted:
				data = packet.make_delete_packet(self.hash)
	
		else:
			if not self.meta_sent:
				if not self.meta_began_at: self.meta_began_at = time.time()
				data = packet.make_meta_packet(self.name, self.hash, self.size, self.type, self.thumb, self.ttl)
		
			elif not self.content_sent:
				key = self.content_sent.keys[random.randrange(0, len(self.content_acks))] #pick any recipient at random
				if not self.content_began_at: self.content_began_at = time.time()
				chunk_id = self.content_sent[key][0] #send the first 
				data = packet.make_chunk_packet(self.hash, chunk_id, self.chunks[chunk_id])
		
			
		return data
		
		
	def request_deletion(self):
		self.delete_request = True
		self.delete_request_began_at = time.time()
		
		
	def got_ack(self, addr, packet_type, chunk_id):
		if packet_type == packet.PACKET_TYPE_ACK_META:
			if addr in self.meta_acks:
				self.meta_acks.remove(addr)
				
				if len(self.meta_acks) == 0: #every recipient has acknowledged the meta data packet
					self.meta_sent = True
				
		elif packet_type == packet.PACKET_TYPE_ACK_CHUNK:
			if addr in self.content_acks:
				self.content_acks[addr].remove(chunk_id)
				if len(self.content_acks[addr]) == 0: self.content_acks.remove(addr) #this peer has acknowledged every chunk
				if len(self.content_acks) == 0: self.content_sent = True
		
		elif packet_type == packet.PACKET_TYPE_ACK_DELETE:
			if addr in self.content_acks:
				self.delete_acks.remove(addr)
				if len(self.delete_acks) == 0:
					self.deleted = True


