#from rawweb import RawWeb
from xml.etree import ElementTree as ET
import urllib
import base64


log_path="burp1.log"

def parse_log(log_path):
	'''
	This fucntion accepts burp log file path.
	and returns a dict. of request and response
	result = {'GET /page.php...':'200 OK HTTP / 1.1....','':'',.....}
	'''
	result = {}
	try:
		with open(log_path): pass
	except IOError:
		print "[+] Error!!! ",log_path,"doesn't exist.."
		exit()
	try:
		tree = ET.parse(log_path)
	except Exception, e:
		print '[+] Oops..!Please make sure binary data is not present in Log, Like raw image dump,flash(.swf files) dump etc'
		exit()
	root = tree.getroot()
	for reqs in root.findall('item'):
		raw_req = reqs.find('request').text
		raw_req = urllib.unquote(raw_req).decode('utf8')
		raw_resp = reqs.find('response').text
		result[raw_req] = raw_resp
	return result
def parseRawHTTPReq(rawreq):
	try:
		raw = raw.decode('utf8')
	except Exception,e:
		raw = rawreq
	global headers,method,body,path
	headers = {}
	sp = raw.split('\n\n',1)
	if len(sp) > 1:
		head = sp[0]
		body = sp[1]
	else :
		head = sp[0]
		body = ""
	c1 = head.split('\n',head.count('\n'))
	method = c1[0].split(' ',2)[0]
	path = c1[0].split(' ',2)[1]
	for i in range(1, head.count('\n')+1):
		slice1 = c1[i].split(': ',1)
		if slice1[0] != "":
			try:
				headers[slice1[0]] = slice1[1]
			except:
				pass
	print headers,method,body,path

result = parse_log(log_path)
for items in result:
	raaw= base64.b64decode(items)
	parseRawHTTPReq(raaw)
