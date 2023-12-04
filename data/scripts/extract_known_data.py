import angr
import re
import bintropy
from statistics import median
from statistics import stdev
from os import listdir
from os.path import isfile, join
#from process_module import angr_analyze

extractCSV = "../known_samples.csv"
#record = "../extracted_record.txt"
known_samples_path = "../known_data"

# Analyze the given ELF in the filepath and put the results in the outputCSV
def analyze(filepath, outputCSV):
  # Angr setup
  try:
    proj = angr.Project(filepath, auto_load_libs=False)
    success = True
  except Exception as e:
    print("Unable to load project: " + str(filepath))
    print(e)
    print("Attempting to specify arch...")
    try:
      proj = angr.Project(filepath, arch='x86_64', auto_load_libs=False)
      print("Successful.")
      success = True
    except Exception as e:
      print("Still unable to load project.")
      print(e)
  if success:
    ss = proj.factory.entry_state()
    simgr = proj.factory.simulation_manager(ss)
    
    generate_data(proj, outputCSV)
  return

# Attributes collected: Minimum address, maximum address, segements, size of each segment, shared objects, requested names, overall entropy, entropy of each segment
def generate_data(angr_proj, outputCSV):
  obj = angr_proj.loader.main_object

  # TODO: Do some optimizing here
  with open(outputCSV, 'a') as extracted_data:
    data = ""
    # Get basic info about the ELF
    min_addr = obj.min_addr
    data = data + str(min_addr)
    max_addr = obj.max_addr
    data = data + ";" + str(max_addr)
    segments = obj.segments
    data = data + ";" + str(segments)
    segments_size = [0]*len(segments)
    for i in range(len(segments)):
      segments_size[i] = segments[i].memsize
    data = data + ";" + str(segments_size)
    shared_objs = [i for i in angr_proj.loader.shared_objects]
    data = data + ";" + ",".join(shared_objs)
    requested_names = angr_proj.loader.requested_names
    data = data + ";" + str(requested_names)
    contents = open(angr_proj.filename, "rb").read()
    # Get entropy info from file ("Linux always considers sectors to be 512 bytes long independently of the devices real block size.")
    e = bintropy.entropy(contents, blocksize=512)
    entropies = e[0]
    avg_entropy = e[1]
    data = data + ";" + str(avg_entropy)
    # Get info about block entropies
    max_entropy = max(entropies)
    data = data + ";" + str(max_entropy)
    min_entropy = min(entropies)
    data = data + ";" + str(min_entropy)
    med_entropy = median(entropies)
    data = data + ";" + str(med_entropy)
    std_entropy = stdev(entropies)
    data = data + ";" + str(std_entropy)
    data = data + ";" + "0" # 0 = not packed; 1 = packed
    #p = re.compile('([A-Za-z]+)_[A-Za-z0-9\.\-]+$')
    #result = p.search(angr_proj.filename)
    #data = data + ";" + result.group(1)
    data = data + ";n/a"

#    analysis_data = path_analysis(angr_proj)
#    data = data + "," + analysis_data
    extracted_data.write(data + "\n")
  return

def main():
  for sample in [f for f in listdir(known_samples_path) if isfile(join(known_samples_path, f))]:
    analyze(known_samples_path + "/" + sample, extractCSV)
  return

if __name__ == '__main__':
  main()
