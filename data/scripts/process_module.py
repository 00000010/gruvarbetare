# For parsing commandline args
import argparse
import zipfile
from pathlib import Path
from os import listdir
from os.path import isfile, join
import angr

csvPath = "./"

def angr_analyze(filepath):
  # Angr setup
  proj = angr.Project(filename, auto_load_libs=False)
  ss = proj.factory.entry_state()
  simgr = proj.factory.simulation_manager(ss)

  generate_data(proj)
  return

def generate_data(angr_proj):
  obj = proj.loader.main_object

  # TODO: Do some optimizing here
  with open(csvPath, 'a') as extracted_data:
    data = ""
    # Get basic info about the ELF
    min_addr = obj.min_addr
    data = data + min_addr
    max_addr = obj.max_addr
    data = data + "," + max_addr
    segments = obj.segments
    data = data + "," + segments
    segments_size = [0]*len(segments)
    for i in range(len(segments)):
      segments_size[i] = segments[i].memsize
    data = data + "," + ";".join(segments_size)
    shared_objs = [i for i in proj.loader.shared_objects]
    data = data + "," + ";".join(shared_objs)
    requested_names = proj.loader.requested_names
    data = data + "," + ";".requested_names

#    analysis_data = path_analysis(angr_proj)
#    data = data + "," + analysis_data
    extracted_data.write(data)
  return

def path_analysis(angr_proj):
  return

# Unzip the sample file and put the data collected from it in the output filepath CSV, then remove sample (zipped file and extraction)
def process_module(filepath, outputPath):
  csvPath = outputPath
  with zipfile.ZipFile(filepath, 'r') as zip_ref:
    extraction_path = './downloaded/' + Path(filepath).stem
    zip_ref.extractall(extraction_path)
  for extracted in [f for f in listdir(extraction_path) if isfile(join)]:
    angr_analyze(filepath)
    try:
      os.remove(filepath)
    except:
      print("Unable to remove file " + filepath)

  return

#def main():
#  parser = argparser.ArgumentParser(prog="process_module")
#  parser.add_argument("-f", "--file", dest="filename", help="zip file to process", metavar="FILE")
#  parser.add_argument("-o", "--output", dest="output", help="CSV file to append sample data", metavar="OUTPUT")
#  args = parser.parse_args()
#  if args.filename:
#      if !args.filename.is_file():
#        print("Error: " + args.filename + " does not exist.")
#        return
#      if !args.output.is_file():
#        print("Error: " + args.output + " does not exist.")
#        return
#
#  process(args.filename, args.output)
#
#  return
#
#if __name__ == '__main__':
#  main()
   
