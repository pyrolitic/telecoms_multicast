
MULTICAST_GROUP = '235.3.13.37'
MULTICAST_PORT = 52300
UNICAST_PORT = 52301

FILE_TYPE_IMAGE = 'image'
FILE_TYPE_AUDIO = 'audio'
FILE_TYPE_VIDEO = 'video'
FILE_TYPE_OTHER = 'other'

FILE_NAME_LONGEST = 300 #characters, not bytes
THUMBNAIL_HIGHEST = 90 #if aspect ratio is not 1:1, this is the maximum the longer side can be
NICK_NAME_LONGEST = 30
UDP_PACKET_SIZE = 65535 - 8 - 20

#in seconds
TIME_TO_MISSING = 5
PRESENCE_INTERVAL = 0.2


#TODO: awkward place for this to be in
import time, math
def time_print(message): 
	now = time.gmtime()
	epoch = time.time()
	print("%s:%s:%s:%s %s" % (now.tm_hour, now.tm_min, now.tm_sec, str(epoch - math.floor(epoch))[2:4], message))
