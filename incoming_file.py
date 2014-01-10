#own files
from proto_file import ProtoFile

#files being received from the network
class IncomingFile(ProtoFile):
	#                  number,    string,    number,    string,    number,       PIL.Image
	def __init__(self, file_type, file_name, file_size, file_hash, time_to_live, thumbnail):
		ProtoFile.__init__(self, file_type, file_name, file_size, time_to_live)
		
		self.hash = file_hash
		self.thumb = thumbnail
		self.complete = False #all chunks are None
		self.complete_at = None #when it was completed and the user could see it
		
	
	#chunk was downloaded, so add it to the list
	def add_chunk(self, chunk_id, chunk):
		if not self.complete:
			if chunk_id >= 0 and chunk_id < len(self.chunks):
				if self.chunks[chunk_id] is None:
					self.chunks[chunk_id] = chunk
					if all(self.chunks): #every chunk is not None; TODO: replace this with a counter, cause it's O(n)
						self.complete = True

				else:
					if self.chunks[chunk_id] == chunk:
						self.message("warning: trying to replace chunk " + str(chunk_id) + " with the same data")

					else:
						self.message("warning: trying to replace chunk " + str(chunk_id) + " with different data")

			else:
				self.message("warning: chunk id " + str(chunk_id) + " out of range")

		else:
			self.message("trying to add chunk to already complete file")


	#write the received file on to the disk			
	def write_to_disk(self, dest_dir):
		if self.complete:
			#add up the size of all the chunks and compare them to the size that we got from the peer
			content_got_size = 0
			for chunk in self.chunks:
				content_got_size += len(chunk)

			if content_got_size == self.size:
				#get the hash of the actual content received and compare it to the hash that we got from the peer
				content_got_hash = self.compute_content_hash()

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
					self.message("error: hash of content(" + content_got_hash.encode('hex') + "does not match the given hash")

			else:
				self.message("error: size of content of does not match the given size")

