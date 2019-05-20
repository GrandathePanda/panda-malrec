import os
import tarfile
import subprocess
import errno
import re
import time
from Queue import Queue, Empty
from threading import Thread
import signal

def dumpmem(panda_path, mem, sample_name, dumppath):
  mkdir_p(dumppath)
  path = os.path.join(dumppath, "memdump")
  panda_args = [panda_path,
                '-m', mem,
                '-replay', sample_name,
                '-panda', "n_instruct_mem:file={}".format(path)
                ]
  tarname = "{}.tar.gz".format(dumppath)

  rr_path = "/".join(dumppath.split("/")[0:-1])

  proc = subprocess.Popen(panda_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=rr_path)

  stdout_q = Queue()
  stderr_q = Queue()
  out_t = Thread(target=enqueue_output, args=(proc.stdout, stdout_q))
  err_t = Thread(target=enqueue_output, args=(proc.stderr, stderr_q))
  out_t.daemon = True
  err_t.daemon = True
  out_t.start()
  err_t.start()

  finished = False
  success = False
  count = 0

  while not finished:
    stdout = get_nowait_q(stdout_q)
    stderr = get_nowait_q(stderr_q)

    print(stdout)

    if stdout and re.search("Replay completed successfully", stdout):
      print("Success case made")
      finished = True
      success = True
      os.kill(proc.pid, signal.SIGKILL)
    else:
      time.sleep(2)
    
  out_t.join()
  err_t.join()

  if success:
    with tarfile.open(tarname, "w:gz") as tar:
      print("Tart")
      tar.add(dumppath, arcname=sample_name)
      print("Tarted")
  else:
    return (False, "Failed to create memdumps for {}".format(sample_name), None)
  
  return (True, "Success for {}".format(sample_name), tarname)

def mkdir_p(path):
  try:
    os.makedirs(path)
  except OSError as exc:
    if exc.errno == errno.EEXIST and os.path.isdir(path):
      pass
    else:
      raise

def enqueue_output(out, queue):
    for line in iter(out.readline, b''):
        queue.put(line)
    out.close()

def get_nowait_q(q):
  try:
    return q.get_nowait()
  except Empty:
    pass