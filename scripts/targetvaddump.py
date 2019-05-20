import os
import sys
import tarfile
import glob
import ConfigParser
import subprocess
import time
import errno
from collections import Counter
from pprint import pprint
from functools import partial
from multiprocessing import Pool

def find_possible_targets(folder_name):
  proc_counts = Counter()

  for memfile in sorted(glob.glob(folder_name + "/*"), key=lambda name: name.split("_")[-1]):
    stdout = vol_pslist(memfile)
    count = len(stdout.split("\n")[2:])
    proc_key = memfile.split("_")[-1]
    proc_counts[proc_key] = count

  count_by_dump = proc_counts.most_common()

  _max = count_by_dump[0]
  _min = count_by_dump[-1]

  if _max[1] == _min[1]:
    raise ValueError("It looks like the EXE was not run in the recording.")

  potential_targets = None

  max_index = int(_max[0].split("_")[-1])
  min_index = int(_max[0].split("_")[-1])

  if max_index > len(count_by_dump) // 2:
    potential_targets = test_for_targets(_min[1], range(max_index, len(count_by_dump)), proc_counts)
  else:
    potential_targets = test_for_targets(_min[1], range(min_index, (len(count_by_dump) // 2) + 1 ), proc_counts)

  return (_min, potential_targets)
  
def test_for_targets(baseline, _range, counts):
  passing = []

  if len(counts.keys()) == 1:
    return [0]

  for index in _range:
    if int(counts[str(index)]) - baseline > 0:
      passing.append(index)

  return passing

def dump_vads(folder_name, _type, os_procs, dump_index):
  vad_path = "/tmp/vads/{}".format(folder_name)

  mkdir_p(vad_path)

  filename = "/tmp/{0}/{1}/memdump_{2}".format(_type, folder_name, dump_index)

  vol_args = ["python",
              conf.get("Main", 'volatility'),
              '-f', filename,
              '--profile', "Win7SP0x86",
              'vaddump', '-D', vad_path
              ]

  subprocess.check_output(vol_args, stderr=subprocess.PIPE)

  for proc_name in os_procs:
    for f in glob.glob(vad_path + "/*{}*".format(proc_name)):
      os.remove(f)

def mkdir_p(path):
  try:
    os.makedirs(path)
  except OSError as exc:
    if exc.errno == errno.EEXIST and os.path.isdir(path):
      pass
    else:
      raise

def proc_list_from_dump_index(folder_name, _type, dump_index):
  memfile = "/tmp/{0}/{1}/memdump_{2}".format(_type, folder_name, dump_index)
  stdout = filter(None, vol_pslist(memfile).split("\n"))
  proc_names = map(lambda ln: ln.split(" ")[1], stdout[2:])

  return proc_names

def vol_pslist(memfile):
    vol_args = ["python",
                conf.get("Main", 'volatility'),
                '-f', memfile,
                '--profile', "Win7SP0x86",
                'pslist',
                ]

    return subprocess.check_output(vol_args, stderr=subprocess.PIPE)

def execute(_type, file):
  with tarfile.open(file) as memdumps:
    try:
      memdumps.extractall(path="/tmp/{}/".format(_type))
    except:
      print("Incomplete targz")

    #not the clearest but basically grabbing the untarred folder name from the tarred folder name
    folder_name = "_".join((".".join(file.split("/")[-1].split(".")[0:-2])).split("_")[0:-1])
    baseline, potential_targets = find_possible_targets("/tmp/{0}/{1}".format(_type, folder_name))
    os_procs = proc_list_from_dump_index(folder_name, _type, baseline[0])

    map(partial(dump_vads, folder_name, _type, os_procs), potential_targets)

def main():
  folder = sys.argv[1]
  _type = "benign"

  global conf

  conf = ConfigParser.ConfigParser()
  conf.read("conf/malrec.config")

  if bool(int(sys.argv[2])):
    _type = "malicious"

  p = Pool(10)
  files = glob.glob(folder + "/*")
  p.map(partial(execute, _type), files)

if __name__ == "__main__":
  main()