#libraries
import hashlib #sha256 for content hashing

#own files
import packet, constant

#common base class for OutgoingFile and IncomingFile
class ProtoFile:
	#                   number,   string,     number,   number
	def __init__(self, file_type, file_name, file_size, time_to_live):
		self.type = file_type
		self.name = file_name
		self.size = file_size
		self.ttl = time_to_live

		chunks_amount = file_size / packet.FILE_CHUNK_SIZE
		if file_size % packet.FILE_CHUNK_SIZE > 0: chunks_amount += 1
		self.chunks = [None] * chunks_amount #array filled with chunks_amount of Nones

		self.path = None #disk file name; will be different from self.name in case there already exists a file named self.name
		self.handle = None #file handle, for disk i/o
		
		self.hash = None #if OutgoingFile, this is the correct hash. if IncomingFile, this is the purported hash from the sender
		

	#sha 256 hash of the contents of the file, if all the chunks are present
	def compute_content_hash(self):
		hash_ob = hashlib.sha256()
		for chunk in self.chunks:
			assert chunk is not None
			hash_ob.update(chunk)

		return hash_ob.digest()


	#@<name>(hash): <message>, for a common template
	def message(self, string):
		constant.time_print("@" + self.name + ' {' + self.hash.encode('hex') + "}:\n\t" + string)


