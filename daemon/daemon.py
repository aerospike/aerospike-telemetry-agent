#!/usr/bin/env python

import sys, os, time, atexit, pwd
from signal import SIGTERM 

class Daemon:
    """
    A generic daemon class.
    
    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, name, pidfile, user, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.name = name
        self.user = user
    
    def daemonize(self):
        """
        do the UNIX double-fork magic, see W. Richard Stevens'
        "Advanced Programming in the UNIX Environment" for details (ISBN 0201563177)
        https://web.archive.org/web/20070410070022/http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit first parent
                sys.exit(0) 
        except OSError, e: 
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
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
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
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
        file(self.pidfile,'w+').write("%s\n" % pid)
        self.demote()

    def demote(self):
        # demote root user to specified user
        try:
            if os.getuid() == 0:
                aero_pw = pwd.getpwnam(self.user)
                os.setgid(aero_pw.pw_gid)
                os.setuid(aero_pw.pw_uid)
        except Exception, ex:
            sys.exit(str(ex))
    
    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        sys.stdout.write("* starting %s\n" % self.name)
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
    
        if pid:
            message = "  ...fail! %s is already running\n"
            sys.stderr.write(message % self.name)
            sys.exit(1)
        
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
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
    
        if not pid:
            message = "  ...fail! %s is not running.\n"
            sys.stderr.write(message % self.name)
            return # not an error in a restart

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

        sys.stdout.write("  ...success!\n")

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

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
            sys.exit(0)
        except TypeError:
            sys.stdout.write("* %s is not running\n" % self.name)
            sys.exit(0)

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
