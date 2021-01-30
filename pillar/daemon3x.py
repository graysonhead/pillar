"""
Based on Generic linux daemon base class for python 3.x.

Downloaded on 30 Jan 2021 from:
https://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/

Modified to add graceful shutdown for child processes.
"""

import sys
import os
import signal
import logging
import multiprocessing


class daemon:
    """A generic daemon class.

    Usage: subclass the daemon class and override the run() method."""

    def __init__(self, pidfile, stdout=None, stderr=None):
        self.logger = logging.getLogger("<daemon>")
        self.stdout = stdout or open(os.devnull, 'a+')
        self.stderr = stderr or open(os.devnull, 'a+')
        self.pidfile = pidfile
        self.shutdown_callback = multiprocessing.Event()
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)

    def daemonize(self):
        """Deamonize class. UNIX double fork mechanism."""

        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as err:
            sys.stderr.write('fork #1 failed: {0}\n'.format(err))
            sys.exit(1)

            # decouple from parent environment
            os.chdir('/')
            os.setsid()
            os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:

                # exit from second parent
                sys.exit(0)
        except OSError as err:
            sys.stderr.write('fork #2 failed: {0}\n'.format(err))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(self.stdout.fileno(), sys.stdout.fileno())
        os.dup2(self.stderr.fileno(), sys.stderr.fileno())

        pid = str(os.getpid())
        with open(self.pidfile, 'w+') as f:
            f.write(pid + '\n')

    def delpid(self):
        self.logger.debug("Removing PID file.")
        os.remove(self.pidfile)

    def start(self):
        """Start the daemon."""

        # Check for a pidfile to see if the daemon already runs
        try:
            with open(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None

        if pid:
            message = "pidfile {0} already exist. " + \
                "Daemon already running?\n"
            sys.stderr.write(message.format(self.pidfile))
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self, *args):
        """Stop the daemon."""
        self.logger.info("Stopping.")
        self.stop_child_procs()

        # Get the pid from the pidfile
        try:
            with open(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None

        if not pid:
            message = "pidfile {0} does not exist. " + \
                "Daemon not running?\n"
            sys.stderr.write(message.format(self.pidfile))
            return  # not an error in a restart

        # Try killing the daemon process
        self.shutdown_callback.set()
        self.delpid()

    def stop_child_procs(self):
        """Override with method that stops child processes"""

    def restart(self):
        """Restart the daemon."""
        self.stop()
        self.start()

    def run(self):
        """You should override this method when you subclass Daemon.

        It will be called after the process has been daemonized by
        start() or restart()."""
