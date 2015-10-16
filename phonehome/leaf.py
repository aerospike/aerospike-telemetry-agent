import hashlib
import logging
import os
import platform
import socket
import struct

from cpuinfo import cpu, cpuinfo

#--------------------------------------------------------------------------------
# ENUMS
#--------------------------------------------------------------------------------

class RACK_AWARE_T:
    NOT_RA, STATIC, DYNAMIC = range(3)

#--------------------------------------------------------------------------------
# HELPERS
#--------------------------------------------------------------------------------

def anonymize_data(data):
    return str(hashlib.md5(data).hexdigest())

def anonymize_ip(ip_port_pair):
    """
    Takes a string of the form <ip address>:<port>
    Returns a string of the form <unique id>:<port>
    """
    if len(ip_port_pair) == 0:
        return
    else:
        try:
            ip, port = ip_port_pair.split(":")
        except:
            logging.exception("Problem parsing ip/port pair.")
        else:
            return anonymize_data(ip) + ":" + str(port)

def decode_ip_addr(ipaddr):
    """
    From PSI -- iddecode
    """
    d = ipaddr & 0xff
    ipaddr >>= 8
    c = ipaddr & 0xff
    ipaddr >>= 8
    b = ipaddr & 0xff
    ipaddr >>= 8
    a = ipaddr & 0xff
    return str(a) + "." + str(b) + "." + str(c) + "." + str(d)

def decode_node_id(node_id, ra):
    """
    Take the node.
    Return a string in the format:
        Not rack aware -- <fabric port>:<MAC address>
        RA Static      -- <fabric port>:<group id>:<node>
        RA Dynamic     -- <fabric port>:<group id>:<ip>

    All fields except the fabric port are anonymized using the md5 hash
    function.

    Logic from PSI -- iddecode
    """
    # Pad out address to 16 bytes
    nid = '0' * (16 - len(node_id)) + node_id

    # Get IP address --- the first 4 bytes
    port = str(int(nid[:4], 16))

    if ra == RACK_AWARE_T.NOT_RA:
        # Get MAC address
        MAC = nid[14:16]
        for i in xrange(12,3,-2):
            MAC += ':' + nid[i:i+2]
        return port + ':' + anonymize_data(MAC)
    elif ra > RACK_AWARE_T.NOT_RA: # RACK AWARE
        # Get group and node id
        group_id = int(nid[4:8], 16)
        node_id = int(nid[8:17], 16)
        if ra == RACK_AWARE_T.STATIC:
            node_ip_str = decode_ip_addr(node_id)
            return port + ':' + anonymize_data(node_ip_str)
        elif ra == RACK_AWARE_T.DYNAMIC:
            return port + ':' + anonymize_data(group_id) + ':' + anonymize_data(node_id)

    logging.info("Unknown node mode. Not decoding node id.")
    return node_id

def semicolon_list_to_dict(semicolon_list):
    """
    Convert a semicolon delimited list of the form METRIX:VALUE to a python
    dictionary.
    """
    out = {}
    for metric_value in semicolon_list.split(";"):
        metric, value = metric_value.split("=")
        out[metric] = value
    return out

def check_statsStr(statsStr, stat):
    if (statsStr == None or statsStr == -1):
        logging.info("no stats for " + stat)
        return False
    return True

def g_partition(s, sep):
	return( s.partition(sep) )

def receivedata(sock, sz):
	pos = 0
	while pos < sz:
		chunk = sock.recv(sz - pos)
		if pos == 0:
			data = chunk
		else:
			data += chunk
		pos += len(chunk)
	return data

#--------------------------------------------------------------------------------
# LEAFLINE
#--------------------------------------------------------------------------------

class LeafLine:
    """Phone line to the local leaf."""
    def __init__(self, port, host):
        self.port = port
        self.host = host
        self.uptime = None # If this goes backwards, resend the config.

    def createInfoSocket(self):
        try:
            self.info_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.info_socket.settimeout(0.5)
            logging.debug("About to connect to info socket.")
            self.info_socket.connect((self.host, int(self.port) ))
        except Exception:
            logging.exception("Exception connecting to socket.")

    def closeSocket(self):
        logging.debug("Closing info socket.")
        self.info_socket.close()
        self.info_socket = None

    def getInfo(self, names):
        """Request info from ASD instance."""
        # Passed a name: created output buffer
        q = (2 << 56) | (1 << 48) | (len(names) + 1)
        fmtStr = "! Q %ds B" % len(names)
        buf = struct.pack(fmtStr, q, names, 10 )

        # request over TCP
        try:
            self.info_socket.send(buf)
            # get response
            rsp_hdr = self.info_socket.recv(8)
            q = struct.unpack_from("! Q",rsp_hdr, 0)
            sz = q[0] & 0xFFFFFFFFFFFF
            logging.debug("Info response size %d", sz)
            if sz > 0:
                rsp_data = receivedata(self.info_socket, sz)
            else:
                rsp_data = None
        except Exception:
            logging.exception("Exception with info request.")
            return -1

        if rsp_data == -1 or rsp_data is None:
            logging.debug("No response data.")
            return -1

        lines = rsp_data.split("\n")
        name, sep, value = g_partition(lines[0],"\t")

        if name != names:
            logging.error("problem: requested name %s got name %s" % (names, name))
            return(-1)
        return value

    def logMessage(self, message):
        command = "log-message:message=%s;who=%s" % (message, "Aerospike Telemetry Agent")
        self.createInfoSocket()
        self.getInfo(command)
        self.closeSocket()

    def connectedToService(self):
        # Check if the info command returns.
        try:
            self.createInfoSocket()
            statsStr = self.getInfo("service")
            self.closeSocket()
            return check_statsStr(statsStr, "service")
        except:
            logging.debug("Failed trying to connect to server")
            return False

    def fetchInfo(self):
        self.createInfoSocket()
        infoMap = self.fetchInfoMain()
        self.closeSocket()
        return infoMap

    def fetchInfoMain(self):
        fields = {} # name , value hash of current statistics

        # SERVICE(S)
        statsStr = self.getInfo("service")
        if not check_statsStr(statsStr, "service"):
            return None
        else:
            fields['service'] = ""
            for ip_addr in statsStr.split(";"):
                fields['service'] += anonymize_data(ip_addr)

        statsStr = self.getInfo("services")
        if check_statsStr(statsStr, "services"):
            fields['services'] = ""
            for ip_addr in statsStr.split(";"):
                fields['services'] += anonymize_data(ip_addr)

        # STATISTICS
        statsStr = self.getInfo("statistics")
        if not check_statsStr(statsStr, "statistics"):
            return None
        else:
            fields['statistics'] = semicolon_list_to_dict(statsStr)
            # Anon. certain fields.
            try:
                fields['statistics']['paxos_principal'] = anonymize_data(fields['statistics']['paxos_principal'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymized data', str(e))

        # CONFIG
        statsStr = self.getInfo("get-config")
        if not check_statsStr(statsStr, "config"):
            return None
        else:
            fields['config'] = semicolon_list_to_dict(statsStr)
            # Anon. certain fields. Fields not guaranteed to exist.
            try:
                fields['config']['heartbeat-address'] = anonymize_data(fields['config']['heartbeat-address'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymized data', str(e))
            try:
                fields['config']['mesh-seed-address-port'] = anonymize_ip(fields['config']['mesh-seed-address-port'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymized data', str(e))
            try:
                fields['config']['mesh-address'] = anonymize_data(fields['config']['mesh-address'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymized data', str(e))

        # NODE
        statsStr = self.getInfo("node")
        if not check_statsStr(statsStr, "node"):
            return None
        else:
            ra = RACK_AWARE_T.NOT_RA
            if fields['config']['paxos-protocol'] == 'v4': # Check if rack aware.
                if fields['config']['mode'] == 'static':
                    ra = RACK_AWARE_T.STATIC
                elif fields['config']['mode'] == 'dynamic':
                    ra = RACK_AWARE_T.DYNAMIC
                else: # Unknown mode
                    logging.info("Unknown mode [%s]", fields['config']['mode'])
            fields['node'] = decode_node_id(statsStr, ra)
            logging.info("Contacted local node: %s" % (fields['node']))

        # Namespaces
        statsStr = self.getInfo("namespaces")
        if not check_statsStr(statsStr, "namespaces"):
            return None
        else:
            fields['namespaces'] = statsStr.split(";")

        # Storage
        storage = {}
        if 'namespaces' in fields:
            for ns in fields['namespaces']:
                statsStr = self.getInfo("namespace/" + ns)
                if not check_statsStr(statsStr, "namespace " + ns):
                    return None
                else:
                    storage[ns] = semicolon_list_to_dict(statsStr)
            fields['storage'] = storage

        # Queries
        queries = {}
        statsStr = self.getInfo("throughput:hist=query")
        if not check_statsStr(statsStr, "throughput hist"):
            return None
        else:
            queries['throughput'] = statsStr
        statsStr = self.getInfo("latency:hist=query")
        if not check_statsStr(statsStr, "latency hist"):
            return None
        else:
            queries['sindex'] = statsStr
        statsStr = self.getInfo("sindex")
        if not check_statsStr(statsStr, "sindexes"):
            return None
        else:
            queries['sindex'] = statsStr
            sindexes = {}
            for si in statsStr.split(";")[:-1]: # For some reason, the returned string ends in ';', hence the -1
                sifieldskv = si.split(":")
                sifields = {}
                for sif in sifieldskv:
                    k, v = sif.split("=")
                    sifields[k] = v
                statsStr = self.getInfo("sindex/" + sifields['ns'] + "/" + sifields['indexname'])
                if not check_statsStr(statsStr, "sindex " + sifields['indexname']):
                    return None
                else:
                    sindexes[sifields['indexname']] = semicolon_list_to_dict(statsStr)
            queries['sindexes'] = sindexes
        fields['queries'] = queries

        # System
        system = {'name': os.name,
                  'system': platform.system(),
                  'release': platform.release()}
        system['CPU information'] = []
        for name in dir(cpuinfo):
            if name[0] == '_' and name[1] != '_':
                r = getattr(cpu,name[1:])()
                if r:
                    if r!=1:
                        system['CPU information'].append('%s=%s' %(name[1:],r))
                    else:
                        system['CPU information'].append(name[1:])
        system['CPU information'].append(cpu.info)
        fields['system'] = system

        # Don't resend data if it likely hasn't changed.
        prev_uptime = self.uptime
        self.uptime = int(fields['statistics']['uptime'])
        if prev_uptime != None and prev_uptime < self.uptime:
            del fields['config']
            del fields['system']

        return fields

