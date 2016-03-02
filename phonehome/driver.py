#!/usr/bin/python

import sys
import time
import logging

from parser import Parser
from home import HomeLine
from leaf import LeafLine, anonymize_my_ip_addr
from . import __version__ as version
from . import HOMEURLPATH as homeUrlPath
from . import LOGFILETEXT as logFileText

#--------------------------------------------------------------------------------
# Driver
#--------------------------------------------------------------------------------

class TelemetryAgent:
    def __init__(self, options):
        self.options = options
        self.homeConnection = HomeLine(options['home-url'] + homeUrlPath, options['proxy'], options['cafile'])
        self.leafAddress = "127.0.0.1"

    def wait_for_leaf_connection(self, first_time=False):
        """
        Wait for the Aerospike server node to come online.
        """
        backoff = 1
        while not self.leafConnection.connectedToService():
            logging.info("Attempting to connect to ASD (backoff %d)." % backoff)
            if not self.options['disable']:
                logging.info("Sending back status: Connecting to ASD.")
                self.phonehome({"telemetry-agent-status": "Connecting to ASD."})
            time.sleep(backoff)
            backoff = min(backoff * 2, self.options['interval'])
        logging.info("Connected to ASD.")
        if not self.options['disable']:
            logging.info("Sending back status: Connected to ASD.")
            self.phonehome({"telemetry-agent-status": "Connected to ASD."})
        if first_time:
            self.alert_asd_of_logging_status()

    def alert_asd_of_logging_status(self):
        # Check if collection is enabled
        if self.options['disable']:
            self.leafConnection.logMessage(logFileText % "INACTIVE")
            logging.info("Aerospike Telemetry Agent not enabled. Shutting down.")
            exit(0)
        else:
            self.leafConnection.logMessage(logFileText % "ACTIVE")
            logging.info("Aerospike Telemetry Agent enabled. Collecting statistics.")

    def phonehome(self, infoMap):
        # add version, interval, and email address (if supplied) into the param list
        infoMap["telemetry-agent-version"] = version
        infoMap["interval"] = str(int(self.options['interval']))
        if self.options['email']:
            infoMap["email"] = self.options['email']

        # Unix Epoch Time
        infoMap['unix-epoch-time'] = str(int(time.time()))

        # Anonymized IP address of sender
        infoMap['telemetry-agent-ip-address'] = anonymize_my_ip_addr()

        blob = self.homeConnection.contact(infoMap)
        if blob == None:
            # Didn't get anything back from Home.
            # Just try to reconnect and wait for next time around.
            self.homeConnection = HomeLine(self.options['home-url'] + homeUrlPath, self.options['proxy'], self.options['cafile'])

    def run(self):
        # Get info port of ASD.
        node_init_path = self.options['config-file']
        configParser = Parser(node_init_path)
        if (configParser.parse() != 0):
            logging.critical("Port not found in config file.")
            sys.exit(-1)
        logging.info("Leaf Node port: %s. Home server: %s " % (configParser.port, self.options['home-url']))

        # Get leaf connection.
        self.leafConnection = LeafLine(configParser.port, self.leafAddress)
        self.wait_for_leaf_connection(True)

        # Collect data.
        while True:
            try:
                infoMap = self.leafConnection.fetchInfo()
            except:
                logging.warning("Cannot contact ASD.")
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.exception("Unexpected error fetching info from ASD.")
                infoMap = None

            if infoMap:
                self.phonehome(infoMap)
            else:
                # Report ASD is down.
                logging.info("Sending back status: ASD is down.")
                self.phonehome({"telemetry-agent-status": "ASD is down."})

                # Attempt to reconnect.
                self.leafConnection = LeafLine(configParser.port, self.leafAddress)
                self.wait_for_leaf_connection()

            time.sleep(self.options['interval'])
