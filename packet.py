#libraries
import struct #low level packing

#own files
import constant

#packet types
PACKET_TYPE_PRESENCE = 0 #reminder that we're in the network, and possibly nickname change
PACKET_TYPE_META = 1 #file metadata
PACKET_TYPE_CHUNK = 2 #file content chunk
PACKET_TYPE_DELETE = 3 #ask the receiver to delete the file
PACKET_TYPE_ACK_META = 4 #acknowledgement for file metadata
PACKET_TYPE_ACK_CHUNK = 5 #acknowledgement for a content chunk
PACKET_TYPE_ACK_DELETE = 6 #acknowledgement having deleted a file


#codec objects for the different types of packets. all types are unsigned

#type must be PACKET_TYPE_PRESENCE
#type, name length, name (separate)
presence_struct = struct.Struct(">H")
def make_presence_packet(peer_name):
	nick = peer_name[:constant.NICK_NAME_LONGEST] if len(peer_name) > constant.NICK_NAME_LONGEST else peer_name #truncate to NICK_NAME_LONGEST characters
	data = str(PACKET_TYPE_PRESENCE)
	data += presence_struct.pack(len(nick))
	data += nick.encode('utf8')
	return data


#file meta data, sent to initialize a file transmission, to let the receivers know about the file. 
#type(1), content length(8), content hash(32), file type(1), thumbnail width(1), height(1), file name length(2), time to live(4), file name (varies), thumbnail data (varies)
#thumbnail can be missing (None), in which case width and height are 0 and thumbnail data has 0 length
meta_struct = struct.Struct(">Q32pBBBHI")
META_MAX_THUMB_SIZE = constant.THUMBNAIL_HIGHEST * constant.THUMBNAIL_HIGHEST * 3
def make_meta_packet(file_name, file_hash, file_size, file_type, thumbnail, time_to_live):	
	#type must be PACKET_TYPE_META, encoded file name and thumbnail data cannnot exceed 65461 bytes
	
	#truncate name to META_MAX_NAME_SIZE
	#http://stackoverflow.com/questions/1809531/truncating-unicode-so-it-fits-a-maximum-size-when-encoded-for-wire-transfer
	name = file_name if len(file_name) < constant.FILE_NAME_LONGEST else file_name[:constant.FILE_NAME_LONGEST]
	encoded_name = name.encode('utf8')
	
	thumb_w = 0
	thumb_h = 0
	
	if thumbnail:
		thumb_w = thumbnail.size[0]
		thumb_h = thumbnail.size[1]
	
	data = str(PACKET_TYPE_META)
	data += meta_struct.pack(file_size, file_hash, file_type, thumb_w, thumb_h, len(encoded_name), time_to_live)
	data += encoded_name
	if thumbnail is not None: data += thumbnail.tostring() #uncompressed
	return data
		

#file content chunk, sent after meta data. type must be PACKET_TYPE_CHUNK
#type(1), file content hash(32), chunk id(4), chunck length(2), data (varies, separate)
chunk_struct = struct.Struct(">32pIH")
def make_chunk_packet(file_hash, chunk_id, chunk):
	data = str(PACKET_TYPE_CHUNK)
	data += chunk_struct.pack(file_hash, chunk_id, len(chunk))
	data += chunk
	return data


#file deletion request
#type(1), content hash(32)
delete_struct = struct.Struct(">32p")
def make_delete_packet(file_hash):
	data = str(PACKET_TYPE_DELETE)
	data += delete_struct.pack(file_hash)
	return data


#acknowledgements, sent when:
#1. metadata was received (PACKET_TYPE_ACK_META, chunk_id is set to 0)
#2. a chunk is received (PACKET_TYPE_ACK_CONTENT)
#3. a file was deleted on request (PACKET_TYPE_ACK_DELETED, chunk_id is set to 0)
#type(1), file content hash(32), chunk index(4)
ack_struct = struct.Struct(">32pI")
def make_ack_packet(file_hash, packet_type, chunk_id = -1):
	ack_id = chunk_id
	if packet_type == PACKET_TYPE_ACK_CONTENT: ack_id = chunk_id
	
	data = str(packet_type)
	data += ack_struct.pack(file_hash, ack_id)
	return data
	

FILE_CHUNK_SIZE = constant.UDP_PACKET_SIZE - 1 - chunk_struct.size #1 is for packet type; max size of a chunk. the final chunk can be smaller

