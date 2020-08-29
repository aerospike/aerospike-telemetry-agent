import logging
import os
import pprint
import signal
import sys

#--------------------------------------------------------------------------------
# Module variables
#--------------------------------------------------------------------------------

__version__ = "1.0.10"
HOMEURLPATH = ":8192/telemetry/v1"
LOGFILETEXT = "Aerospike anonymous data collection is %s. For further information, see http://aerospike.com/aerospike-telemetry"

#--------------------------------------------------------------------------------
# Imports
#--------------------------------------------------------------------------------

try:
    from urlparse import urlparse
except:
    from urllib.parse import urlparse

from .driver import TelemetryAgent

#--------------------------------------------------------------------------------
# Global vars
#--------------------------------------------------------------------------------

LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

def signal_term_handler(sig, frame):
    logging.info("Got SIGTERM. Exiting.")
    sys.exit(0)

def init(options):
    # Configure logging before daemonizing and potentially dropping privileges.
    logFormat = '[%(asctime)s] p%(process)s %(levelname)s: (%(filename)s:%(lineno)d) %(message)s'
    datefmt = '%m-%d %H:%M:%S'
    if options['logfile'] == 'out' or options['fgdaemon']:
        logging.basicConfig(format=logFormat, datefmt=datefmt, stream=sys.stdout, level=LEVELS.get(options['loglevel']))
    else:
        logging.basicConfig(format=logFormat, datefmt=datefmt, filename=options['logfile'], level=LEVELS.get(options['loglevel']))
    logging.info("Aerospike Telemetry Agent %s initialized.", __version__)
    logging.info("Python version: %s", sys.version)

def run(options):
    # Validate url.
    url = urlparse(options['home-url'])
    if not bool(url.scheme):
        logging.critical("No scheme for url [%s].", options['home-url'])
        sys.exit(-1)
    if not bool(url.netloc):
        logging.excection("No netloc for url [%s].", options['home-url'])
        sys.exit(-1)

    # Handle SIGTERM
    signal.signal(signal.SIGTERM, signal_term_handler)

    # Phone home.
    logging.info("Starting to phone home.")
    logging.info("Options = \n%s", pprint.pformat(options))
    telemetry_agent = TelemetryAgent(options)
    try:
        telemetry_agent.run()
    except KeyboardInterrupt:
        logging.info("Caught KeyboardInterrupt. Exiting.")
        logging.info("Phone home ended.")
        try:
            sys.exit(0)
        except:
            os._exit(0)
