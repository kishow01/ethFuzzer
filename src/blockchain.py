import subprocess

from util import DEFAULT_BLOCKCHAIN_KEY_LOCATION, DEFAULT_BLOCKCHAIN_PORT

class Ganache:
    def start(self):
        from time import sleep
        self.proc = subprocess.Popen(['ganache-cli', '--account_keys_path', DEFAULT_BLOCKCHAIN_KEY_LOCATION, '--port', str(DEFAULT_BLOCKCHAIN_PORT)], 
                                     stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        sleep(5)

    def end(self):
        self.proc.terminate()