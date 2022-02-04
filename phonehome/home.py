try:
    import httplib as httpcli
except:
    import http.client as httpcli
import json
import logging
import pprint
import ssl
try:
    import urllib2 as urlreq
except:
    import urllib.request as urlreq

class HomeLine:
    def __init__(self, url, proxy, cafile):
        self.url = url
        self.proxy = proxy
        if proxy:
            logging.info("Using HTTPS proxy: " + proxy)
            proxy_handler = urlreq.ProxyHandler({'https': proxy})
            opener = urlreq.build_opener(proxy_handler)
            urlreq.install_opener(opener)
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

        logging.info("Home Response [%s]" % (response.decode('utf-8')))
        return response

    def postInfo(self, requestParams):
        logging.info("About to phone home to [%s].", self.url)

        req = urlreq.Request(self.url)
        req.add_header('Content-Type', 'application/json')
        resp = None

        try:
            resp = urlreq.urlopen(req, json.dumps(requestParams).encode("utf-8"), timeout = 30, **self.kwargs)
            resp = resp.read()
        except urlreq.HTTPError as e:
            logging.error("HTTPError: %s", str(e.code))
        except urlreq.URLError as e:
            logging.error("URLError: %s", str(e.reason))
        except httpcli.HTTPException as e:
            logging.error("HTTPException: %s", str(e))
        except Exception as e:
            logging.exception("Unexpected error: %s", str(e))

        return resp
