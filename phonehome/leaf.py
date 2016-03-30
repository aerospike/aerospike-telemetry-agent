import datetime
import hashlib
import logging
import os
import platform
import socket
import struct
import sys

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

def my_ip_addr():
    """
    Return the default IP address used for Internet connections, falling back to localhost address upon error.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 0)) # connecting to a UDP address doesn't send any packets
        ip_addr = s.getsockname()[0]
    except:
        ip_addr = "127.0.0.1"
    finally:
        s.close()
    return ip_addr

def anonymize_my_ip_addr():
    return anonymize_data(my_ip_addr())

def anonymize_ip_port(ip_port_pair):
    """
    Takes a string of the form <IP address>:<port>
    Returns a string of the form <unique id>:<port>
    """
    if len(ip_port_pair) == 0:
        return
    else:
        try:
            ip, port = ip_port_pair.split(":")
        except:
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Problem parsing ip/port pair.")
        else:
            return anonymize_data(ip) + ":" + str(port)

def decode_ip_addr(ipaddr):
    """Convert 32-bit numeric IPv4 address to string of 4 dot-separated octets."""
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
    Take the node id and Rack Aware format "ra".
    Return a string according to the specified format:
        Not Rack Aware -- <fabric port>:<MAC address>
        RA Static      -- <fabric port>:<group id>:<node id>
        RA Dynamic     -- <fabric port>:<group id>:<IP address>

    All fields except the fabric port are anonymized using the md5 hash
    function.
    """
    # Left pad node id with zeroes out to 16 hex characters
    nid = '0' * (16 - len(node_id)) + node_id

    # Get service port from the first 4 hex characters
    port = str(int(nid[:4], 16))

    if ra == RACK_AWARE_T.NOT_RA:
        # Get MAC address
        MAC = nid[14:16]
        for i in xrange(12,3,-2):
            MAC += ':' + nid[i:i+2].upper()
        return port + ':' + anonymize_data(MAC)
    elif ra > RACK_AWARE_T.NOT_RA: # Rack Aware formats
        # Get group id and node id or IP address
        group_id = int(nid[4:8], 16)
        node_id = int(nid[8:17], 16)
        if ra == RACK_AWARE_T.STATIC:
            node_ip_str = decode_ip_addr(node_id)
            return port + ':' + anonymize_data(group_id) + ':' + anonymize_data(node_ip_str)
        elif ra == RACK_AWARE_T.DYNAMIC:
            return port + ':' + anonymize_data(group_id) + ':' + anonymize_data(node_id)

    logging.info("Unknown node id format ~~ Not decoding node id.")
    return node_id

def semicolon_list_to_dict(semicolon_list):
    """
    Convert a semicolon-delimited list of items of the form <metric>:<value>
    to a Python dictionary.
    """
    out = {}
    for metric_value in semicolon_list.split(";"):
        metric, value = metric_value.split("=")
        if metric in out:
            out[metric] += ';' + value
        else:
            out[metric] = value
    return out

def check_statsStr(statsStr, stat):
    if (statsStr == None or statsStr == -1 or statsStr == ""):
        logging.debug("no stats for " + stat)
        return False
    return True

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
        self.asd_uptime = None # If this goes backwards, resend the config.
        self.next_full_send_time = datetime.datetime.now() # Send full data when Telemetry Agent starts up
        self.full_send_interval = datetime.timedelta(days=1) # Send full data once per day

    def createInfoSocket(self):
        try:
            self.info_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.info_socket.settimeout(0.5)
            logging.debug("About to connect to info socket.")
            self.info_socket.connect((self.host, int(self.port)))
        except Exception:
            if logging.getLogger().isEnabledFor(logging.DEBUG):
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
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Exception with info request.")
            return -1

        if rsp_data == -1 or rsp_data is None:
            logging.debug("No response data.")
            return -1

        lines = rsp_data.split("\n")
        name, sep, value = lines[0].partition("\t")

        if name != names:
            logging.error("problem: requested name %s got name %s" % (names, name))
            return -1
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

        # Configuration
        statsStr = self.getInfo("get-config")
        if check_statsStr(statsStr, "config"):
            fields['config'] = semicolon_list_to_dict(statsStr)
            # Anonymize certain fields (which are not guaranteed to exist.)
            try:
                fields['config']['service-address'] = anonymize_data(fields['config']['service-address'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymize data', str(e))
            try:
                fields['config']['access-address'] = anonymize_data(fields['config']['access-address'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymize data', str(e))
            try:
                fields['config']['alternate-address'] = anonymize_data(fields['config']['alternate-address'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymize data', str(e))
            try:
                fields['config']['heartbeat-address'] = anonymize_data(fields['config']['heartbeat-address'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymize data', str(e))
            try:
                fields['config']['heartbeat-interface-address'] = anonymize_data(fields['config']['heartbeat-interface-address'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymize data', str(e))
            try:
                if fields['config']['mesh-seed-address-port']:
                    statsStr = fields['config']['mesh-seed-address-port']
                    result = ""
                    for ip_port in statsStr.split(";"):
                        if result:
                            result += ";"
                        result += anonymize_ip_port(ip_port)
                    fields['config']['mesh-seed-address-port'] = result
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymize data', str(e))
            try:
                fields['config']['mesh-address'] = anonymize_data(fields['config']['mesh-address'])
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymize data', str(e))

        # Node
        statsStr = self.getInfo("node")
        if check_statsStr(statsStr, "node"):
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

        # Cluster
        fields['succession-list'] = ""
        statsStr = self.getInfo("get-sl:")
        if check_statsStr(statsStr, "succession list"):
            for node_id in statsStr.split(","):
                if fields['succession-list']:
                    fields['succession-list'] += ','
                fields['succession-list'] += decode_node_id(node_id, ra)

        # Service(s)
        fields['service'] = ""
        statsStr = self.getInfo("service")
        if check_statsStr(statsStr, "service"):
            fields['service'] = anonymize_ip_port(statsStr)

        fields['services'] = ""
        statsStr = self.getInfo("services")
        if check_statsStr(statsStr, "services"):
            for ip_port in statsStr.split(";"):
                if fields['services']:
                    fields['services'] += ';'
                fields['services'] += anonymize_ip_port(ip_port)

        fields['services-alternate'] = ""
        statsStr = self.getInfo("services-alternate")
        if check_statsStr(statsStr, "services-alternate"):
            for ip_port in statsStr.split(";"):
                if fields['services-alternate']:
                    fields['services-alternate'] += ';'
                fields['services-alternate'] += anonymize_ip_port(ip_port)

        fields['services-alumni'] = ""
        statsStr = self.getInfo("services-alumni")
        if check_statsStr(statsStr, "services-alumni"):
            for ip_port in statsStr.split(";"):
                if fields['services-alumni']:
                    fields['services-alumni'] += ';'
                fields['services-alumni'] += anonymize_ip_port(ip_port)

        # Statistics
        statsStr = self.getInfo("statistics")
        if check_statsStr(statsStr, "statistics"):
            fields['statistics'] = semicolon_list_to_dict(statsStr)
            # Anonymize certain fields.
            try:
                fields['statistics']['paxos_principal'] = decode_node_id(fields['statistics']['paxos_principal'], ra)
            except KeyError, e:
                logging.debug('key error on [%s] encountered while attempting to anonymize data', str(e))

        # Namespaces
        namespaces = {}
        statsStr = self.getInfo("namespaces")
        if check_statsStr(statsStr, "namespaces"):
            namespace_names = statsStr.split(";")
            for ns in namespace_names:
                statsStr = self.getInfo("namespace/" + ns)
                if check_statsStr(statsStr, "namespace " + ns):
                    # Note:  Anonymize the namespace name.
                    namespaces[anonymize_data(ns)] = semicolon_list_to_dict(statsStr)
        fields['namespaces'] = namespaces

        # Queries
        queries = {}
        statsStr = self.getInfo("throughput:hist=query")
        if check_statsStr(statsStr, "throughput hist"):
            queries['throughput'] = statsStr
        statsStr = self.getInfo("latency:hist=query")
        if check_statsStr(statsStr, "latency hist"):
            queries['latency'] = statsStr
        fields['queries'] = queries

        # UDFs
        udfs = {}
        statsStr = self.getInfo("udf-list")
        udfs['num-udf-files'] = str(len(filter(bool, statsStr.split(';'))))
        fields['udfs'] = udfs

        # Memory
        with open("/proc/meminfo", "r") as infile:
            meminfo_str = infile.read()
        meminfo_lines = filter(bool, meminfo_str.split('\n'))
        meminfo = {}
        for line in meminfo_lines:
            k, v = line.split(':')
            meminfo[k] = v.strip()
        fields['meminfo'] = meminfo

        prev_asd_uptime = self.asd_uptime
        self.asd_uptime = int(fields['statistics']['uptime'])

        # Send additional infrequently-changing or potentially verbose data
        # whenever either the Telemetry Agent or Aerospike Server is restarted,
        # or the full send interval has elapsed.
        now = datetime.datetime.now()
        if prev_asd_uptime == None or prev_asd_uptime > self.asd_uptime or now > self.next_full_send_time:
            self.next_full_send_time = now + self.full_send_interval

            # Secondary Indexes
            sindex_metadata = []
            sindexes = {}
            statsStr = self.getInfo("sindex")
            if check_statsStr(statsStr, "sindex metadata"):
                for si in filter(bool, statsStr.split(";")):
                    si_fields_kv = si.split(":")
                    si_fields = {}
                    ns = indexname = ""
                    for field in si_fields_kv:
                        k, v = field.split("=")
                        # Anonymize certain fields and save some for use below.
                        if k in ('ns', 'set', 'indexname', 'bin', 'path'):
                            if k == 'ns':
                                ns = v
                            elif k == 'indexname':
                                indexname = v
                            v = anonymize_data(v)
                        si_fields[k] = v
                    sindex_metadata.append(si_fields)
                    statsStr = self.getInfo("sindex/" + ns + "/" + indexname)
                    if check_statsStr(statsStr, "sindex " + indexname):
                        # Note:  Use anonymized SIndex name.
                        sindexes[si_fields['indexname']] = semicolon_list_to_dict(statsStr)
            fields['sindex-metadata'] = sindex_metadata
            fields['sindexes'] = sindexes

            # Sets
            sets = []
            statsStr = self.getInfo("sets")
            if check_statsStr(statsStr, "sets"):
                for set in filter(bool, statsStr.split(';')):
                    set_fields_kv = set.split(":")
                    set_fields = {}
                    for field in set_fields_kv:
                        k, v = field.split("=")
                        # Anonymize certain fields.
                        if k in ('ns_name', 'set_name'):
                            v = anonymize_data(v)
                        set_fields[k] = v
                    sets.append(set_fields)
            fields['sets'] = sets

            # Host System Information
            system = {'os-name': os.name,
                      'linux_distribution': platform.linux_distribution(),
                      'platform': sys.platform,
                      'uname': list(platform.uname())}
            # Anonymize node name.
            system['uname'][1] = anonymize_data(system['uname'][1])
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
        else:
            # Allow config. to be used above, but throw it away if it's not being sent.
            del fields['config']

        return fields
