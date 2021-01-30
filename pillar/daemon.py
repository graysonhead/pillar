"""
Loosely based on Generic linux daemon base class for python 3.x.,
as downloaded on 30 Jan 2021 from:
https://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/

Modified to add graceful shutdown for child processes.
"""
from pillar.keymanager import KeyManager
from pillar.config import Config
from pillar.ipfs import IPFSWorker
from pillar.identity import Node
from pillar.db import PillarDataStore
import logging
import multiprocessing
import signal
import time
import sys
import os


class PillarDaemon:

    def __init__(self,
                 config: Config,
                 pidfile: str,
                 stdout,
                 stderr):
        self.logger = logging.getLogger(self.__repr__())
        self.config = config
        self.pidfile = pidfile
        self.stdout = stdout or open(os.devnull, 'a+')
        self.stderr = stderr or open(os.devnull, 'a+')
        self.pds = PillarDataStore(self.config)
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

        self.shutdown_callback.set()
        self.delpid()

    def restart(self):
        """Restart the daemon."""
        self.stop()
        self.start()

    def start_ipfs_workers(self):
        for worker in self.ipfs_workers:
            worker.start()

    def stop_ipfs_workers(self):
        for worker in self.ipfs_workers:
            worker.exit()

    def get_ipfs_workers(self, config: Config):
        workers = []
        for i in range(config.get_value('ipfs_workers')):
            workers.append(IPFSWorker(str(i)))
        return workers

    def stop_child_procs(self):
        self.logger.info("stopping node.")
        self.node.exit()
        self.logger.info("stopping key manager.")
        self.key_manager.exit()
        self.logger.info("stopping ipfs workers.")
        self.stop_ipfs_workers()

    def hodor(self):
        while not self.shutdown_callback.is_set():
            time.sleep(0.1)
        self.logger.info("daemon stopped.")

    def run(self):
        self.key_manager = KeyManager(self.config, self.pds)
        self.node = Node(self.config)
        self.ipfs_workers = self.get_ipfs_workers(self.config)
        self.logger.info("Starting IPFS workers")
        self.start_ipfs_workers()
        self.logger.info("Starting key manager worker")
        self.key_manager.start()
        self.logger.info("Starting node worker")
        self.node.start()
        self.hodor()

    def __repr__(self):
        return "<PillarDaemon>"
