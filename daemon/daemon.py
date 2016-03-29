#!/usr/bin/env python

import sys, os, time, atexit, pwd, grp, logging
from signal import SIGTERM 

class Daemon:
    """
    A generic daemon class.
    
    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, name, pidfile, user, group, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.name = name
        self.user = user
        self.group = group

    def daemonize(self):
        """
        do the UNIX double-fork magic, see W. Richard Stevens'
        "Advanced Programming in the UNIX Environment" for details (ISBN 0201563177)
        https://web.archive.org/web/20070410070022/http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        # When dropping privs., verify the group and user exist before forking, so any error will get printed.
        if os.getuid() == 0:
            if self.group:
                try:
                    self.the_grp = grp.getgrnam(self.group)
                except Exception, ex:
                    msg = "failed to find group \"%s\"" % self.group
                    logging.critical(msg + " [%s]" % str(ex))
                    sys.stdout.write("  ..." + msg + "!\n")
                    sys.exit(1)
            if self.user:
                try:
                    self.the_pwd = pwd.getpwnam(self.user)
                except Exception, ex:
                    msg = "failed to find user \"%s\"" % self.user
                    logging.critical(msg + " [%s]" % str(ex))
                    sys.stdout.write("  ..." + msg + "!\n")
                    sys.exit(1)

        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            logging.critical("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError, e:
            logging.critical("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile, 'w+').write("%s\n" % pid)
        self.demote()

    def demote(self):
        # demote root user to any specified user or group
        try:
            if os.getuid() == 0:
                # drop supplementary groups
                os.setgroups([])
                if self.group:
                    try:
                        os.setgid(self.the_grp.gr_gid)
                    except Exception, ex:
                        logging.critical("failed to set group to \"%s\" [%s]" % (self.group, str(ex)))
                        sys.exit(1)
                if self.user:
                    try:
                        the_pwd = pwd.getpwnam(self.user)
                        os.setuid(self.the_pwd.pw_uid)
                    except Exception, ex:
                        logging.critical("failed to set user to \"%s\" [%s]" % (self.user, str(ex)))
                        sys.exit(1)
            else:
                if self.user or self.group:
                    logging.critical('not privileged ~~ cannot change to user [%s] / group [%s]' % (self.user, self.group))
                    sys.exit(1)
        except Exception, ex:
            logging.critical("daemon.demote() caught exception [%s]" % str(ex))
            sys.exit(1)

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        sys.stdout.write("* starting %s\n" % self.name)
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            sys.stdout.write("  ...%s is already running\n" % self.name)
            return # not an error

        # Start the daemon
        self.init()
        self.daemonize()
        self.run()

    def stop(self):
        """
        Stop the daemon
        """
        sys.stdout.write("* stopping %s\n" % self.name)
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            sys.stdout.write("  ...%s is not running.\n" % self.name)
            return # not an error

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    def try_restart(self):
        """
        Restart the daemon only if already running
        """
        if self.is_running():
            self.restart()

    def is_running(self):
        """
        Is the daemon running?
        """
        try:
            with file(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            return False

        try:
            procfile = open("/proc/%d/status" % pid, 'r')
            procfile.close()
        except IOError, TypeError:
            return False

        return True

    def status(self):
        """
        Status of daemon

        By JH
        """
        try:
            with file(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None

        try:
            procfile = open("/proc/%d/status" % pid, 'r')
            procfile.close()
        except IOError:
            sys.stdout.write("There is no process with the PID Specified in %s\n" % self.pidfile)
            sys.exit(1)
        except TypeError:
            sys.stdout.write("* %s is not running\n" % self.name)
            sys.exit(3)

        sys.stdout.write("* %s is running with PID %d\n" % (self.name, pid))

    def init(self):
        """
        You may override this method when you subclass Daemon. It will be called before the process has been
        daemonized (and has potentially dropped privileges) by start() or restart().
        """

    def run(self):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """
