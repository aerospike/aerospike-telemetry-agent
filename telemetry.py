#!/usr/bin/python
import sys
import ConfigParser
from optparse import OptionParser

from phonehome import init, run
from daemon import daemon

if __name__ == "__main__":
    usage = "Usage: %s [options] <ConfigFile> [<Service Action for Daemon Mode: (start|stop|restart|status)>]" % __file__
    usagenl = usage + "\n"
    optparser = OptionParser(usage=usage, add_help_option=True)
    optparser.add_option("--set-email", dest="email", type="string", metavar="<EMAIL>", help="Set email address.")
    optparser.add_option("--set-loglevel", dest="loglevel", type="string", metavar="<LOGLEVEL>", help="Set log level.")
    optparser.add_option("--set-logfile", dest="logfile", type="string", metavar="<LOGFILE>", help="Set log file.")
    optparser.add_option("--set-frequency", dest="frequency", type="int", metavar="<FREQUENCY>", help="Set logging frequency.")
    optparser.add_option("--disable", dest="disable", action="store_true", default=False, help="Disable Telemetry Agent. (Requires agent restart to take effect.)")
    optparser.add_option("--enable", dest="enable", action="store_true", default=False, help="Enable Telemetry Agent. (Requires agent restart to take effect.)")
    (options, args) = optparser.parse_args()

    # Args.
    if len(args) < 1:
        sys.stderr.write(usagenl)
        sys.stderr.write("\nMissing required configuration file name.\n")
        sys.exit(2)
    config_filename = args[0]

    # Read configuration file.
    config = ConfigParser.ConfigParser()
    try:
        with open(config_filename, 'r') as config_fd:
            config.readfp(config_fd)
    except Exception, ex:
        sys.stderr.write(usagenl)
        sys.stderr.write("\nCould not parse configuration file [%s] --- [%s]\n" % (config_filename, str(ex)))
        sys.exit(0)
    edit_config = False

    # Check options.
    try:
        if options.disable:
            config.set('main', 'disable', 'true')
            edit_config = True
        if options.enable:
            config.set('main', 'disable', 'false')
            edit_config = True
        if options.loglevel:
            config.set('logging', 'loglevel', options.loglevel)
            edit_config = True
        if options.logfile:
            config.set('logging', 'logfile', options.logfile)
            edit_config = True
        if options.frequency:
            config.set('main', 'frequency', options.frequency)
            edit_config = True
        if options.email:
            config.set('main', 'email', options.email)
            edit_config = True
        if edit_config:
            with open(args[0], 'wb') as cf:
                config.write(cf)
            sys.stdout.write("Configuration file [%s] successfully changed.\n" % config_filename)
            exit(0)
    except Exception, ex:
        sys.stderr.write(usagenl)
        sys.stderr.write("\nError writing to configuration file [%s]\n" % str(ex))
        sys.exit(2)

    # Get options
    try:
        opts = {'home-url': config.get('main', 'home-url'),
                'frequency': config.getfloat('main', 'frequency'),
                'email': config.get('main', 'email'),
                'disable': config.getboolean('main','disable'),
                'logfile': config.get('logging', 'logfile'),
                'loglevel': config.get('logging', 'loglevel'),
                'config-file': config.get('asd', 'config-file')}
        user = config.get('main', 'user')
    except ConfigParser.NoOptionError, ex:
        sys.stderr.write(usagenl)
        sys.stderr.write("\nInvalid configuration file [%s] -- Option not found [%s]\n" % (config_filename, str(ex)))
        sys.exit(2)
    except ConfigParser.NoSectionError, ex:
        sys.stderr.write(usagenl)
        sys.stderr.write("\nInvalid configuration file [%s] -- Section not found [%s]\n" % (config_filename, str(ex)))
        sys.exit(2)
    except Exception, ex:
        sys.stderr.write(usagenl)
        sys.stderr.write("\nInvalid configuration file [%s] -- Error [%s]\n" % (config_filename, str(ex)))
        sys.exit(2)

    if len(args) == 2:
        service_action = args[1]

        # Monkey patch init method
        def init_patch(self):
            init(opts)
        daemon.Daemon.init = init_patch

        # Monkey patch run method
        def run_patch(self):
            run(opts)
        daemon.Daemon.run = run_patch

        # Perform service action
        daemon = daemon.Daemon('telemetry', '/var/run/aerospike/telemetry.pid', user)
        if 'start' == service_action:
            daemon.start()
        elif 'stop' == service_action:
            daemon.stop()
        elif 'restart' == service_action:
            daemon.restart()
        elif 'status' == service_action:
            daemon.status()
        else:
            sys.stderr.write(usagenl)
            sys.stderr.write("\nUnknown service action [%s]\n" % service_action)
            sys.exit(2)

        sys.exit(0)
    else:
        sys.stderr.write(usagenl)
        sys.stderr.write("\nIncorrect number of arguments [%d] : %s -- Must supply a single service action for daemon mode.\n" % (len(args), args))
        sys.exit(2)
