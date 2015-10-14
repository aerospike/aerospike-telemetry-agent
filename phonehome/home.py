import logging
import httplib
import urllib2
import json
import pprint

class HomeLine:
	def __init__(self, url):
		self.url = url

	# given an infoStr returned by the local node, call up the HOME server
	def contact(self, infoMap):
		logging.debug("HomeLine.contact: infoMap = %s", pprint.pformat(infoMap, indent=2))

		response = self.postInfo(infoMap);
		if response == None:
			logging.info("Home has no response")
			return None

		logging.info("Home Response [%s]" % (response))
		return response

	def postInfo(self, requestParams):
		logging.info("About to phone home to [%s].", self.url)

		req = urllib2.Request(self.url)
		req.add_header('Content-Type', 'application/json')
		resp = None

		try:
			resp = urllib2.urlopen(req, json.dumps(requestParams))
			resp = resp.read()
		except urllib2.HTTPError, e:
			logging.error("HTTPError: %s", str(e.code))
		except urllib2.URLError, e:
			logging.error("URLError: %s", str(e.reason))
		except httplib.HTTPException, e:
			logging.error("HTTPException")
		except:
			logging.exception("Unexpected error")

		return resp

