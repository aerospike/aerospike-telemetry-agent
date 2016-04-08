import httplib
import json
import logging
import pprint
import ssl
import urllib2

class HomeLine:
	def __init__(self, url, proxy, cafile):
		self.url = url
		self.proxy = proxy
		if proxy:
			logging.info("Using HTTPS proxy: " + proxy)
			proxy_handler = urllib2.ProxyHandler({'https': proxy})
			opener = urllib2.build_opener(proxy_handler)
			urllib2.install_opener(opener)
		self.kwargs = {}
		if cafile and hasattr(ssl, "create_default_context"):
			logging.info("Using CA file: " + cafile)
			ctx = ssl.create_default_context()
			ctx.load_verify_locations(cafile = cafile)
			self.kwargs['context'] = ctx

	# given an infoMap returned by the local node, call up the home server
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
			resp = urllib2.urlopen(req, json.dumps(requestParams), timeout = 30, **self.kwargs)
			resp = resp.read()
		except urllib2.HTTPError, e:
			logging.error("HTTPError: %s", str(e.code))
		except urllib2.URLError, e:
			logging.error("URLError: %s", str(e.reason))
		except httplib.HTTPException, e:
			logging.error("HTTPException: %s", str(e))
		except Exception, e:
			logging.exception("Unexpected error: %s", str(e))

		return resp
