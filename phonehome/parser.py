import logging

class Parser:
	port = ""
	filename = ""

	def __init__(self, filename):
		self.filename = filename

	# return 0 if parsing succeeds
	def parse(self):
		try:
			theFile = open(self.filename, 'r')
			confMode = "top"	# "service" or "network" are the two we care about
			subMode = "none"	# second level mode, set after finding the first level mode

			aLine = theFile.readline()
			while aLine != "":
				aLine = aLine.strip();
				logging.debug("Parser.parser: *** %s ***", aLine)
				isComment = False

				if (aLine.startswith("#")):
					isComment=True
					logging.debug("skipping comment line")
				elif (aLine.startswith("}")):
					confMode = "top"
					subMode = "none"
				elif confMode == "network":
					if (subMode == "service"):
						# already found "service" under network
						if aLine.startswith("port"):
							sss = aLine.split(" ")
							self.port = sss[len(sss) - 1].strip()
							logging.debug("parsed port = %s" % (self.port))
							subMode="none"
							confMode="top"
					else:
						if aLine.startswith("service"):
							subMode = "service"
				elif confMode == "top":
					if aLine.startswith("network"):
						confMode = "network"
					elif aLine.startswith("service"):
						confMode = "service"

				if (isComment == False):
					logging.debug("inputLine: [%s] mode = %s subMode = %s" % (aLine.strip(), confMode, subMode))
				aLine = theFile.readline()

			if (self.port == ""):
				logging.info("could not get service port")
				return -1
		except IOError:
			logging.exception("unable to open server config file ", self.filename)
			return -1

		return 0


