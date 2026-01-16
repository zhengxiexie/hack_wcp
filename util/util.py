import functools
import time

from . import logger
import subprocess
import paramiko

log = logger.get_logger(__name__)


def runcmd(command):
    log.info("run command: %s" % command)
    ret = subprocess.run(command, capture_output=True, text=True, shell=True)
    if ret.returncode == 0:
        return 0, ret.stdout
    return -1, ret.stderr


def runcmd_realtime(command):
    log.info("run command: %s" % command)
    ret = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while True:
        line = ret.stdout.readline()
        if not line:
            break
        log.info(line.decode('utf-8').strip())
    ret.wait()
    if ret.returncode == 0:
        return 0, ret.stdout
    return -1, ret.stderr


def runcmd_remote(command, node):
    log.info("run command: %s on node: %s" % (command, node))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    k = paramiko.RSAKey.from_private_key_file("/root/.ssh/id_rsa")
    ssh.connect(hostname=node, username="root", pkey=k)
    stdin, stdout, stderr = ssh.exec_command(command)
    if stderr.read() == b'':
        return 0, stdout.read().decode('utf-8')
    return -1, None


def wait_and_retry(max_retries=3, retry_interval=10):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retry_num = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retry_num += 1
                    if retry_num > max_retries:
                        print("Maximum number of retries %s "
                              "exceeded, stopping iteration for function %s" %
                              (max_retries, func.__name__))
                        raise e
                    print("Exception %s occurred, retrying after %s seconds" %
                          (e, retry_interval))
                    time.sleep(retry_interval)
        return wrapper
    return decorator
