# For parsing commandline args
import argparse
import pyzipper
from pathlib import Path
from os import listdir
from os.path import isfile, join
from os import remove
import angr
import magic
import shutil

csvPath = "../sample_data.csv"

def angr_analyze(filepath, outputCSV):
  magicString = magic.from_file(filepath)
  if "ELF " in magicString:
    success = False
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
    return True

  return False

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

#    analysis_data = path_analysis(angr_proj)
#    data = data + "," + analysis_data
    extracted_data.write(data + "\n")
  return

def path_analysis(angr_proj):
  return

# Unzip the sample file and put the data collected from it in the output filepath CSV, then remove sample (zipped file and extraction)
def process_module(filepath, outputPath):
  csvPath = outputPath
  print("unzipping " + filepath)
  with pyzipper.AESZipFile(filepath, 'r') as zip_ref:
    extraction_path = './downloaded/' + Path(filepath).stem
    password_bytes = "infected".encode('utf-8')
    zip_ref.setencryption(pyzipper.WZ_AES, nbits=128)
    zip_ref.extractall(extraction_path, pwd=password_bytes)
  for extracted in [f for f in listdir(extraction_path) if isfile(join(extraction_path, f))]:
    success = angr_analyze(extraction_path + "/" + extracted, csvPath)
#    if not success:
      # Remove zip file
    try:
      remove(filepath)
    except Exception as e:
      print("Unable to remove file " + filepath)
      print(e)
    # Remove sample folder
    try:
      shutil.rmtree(extraction_path)
    except Exception as e:
      print("Unable to remove folder " + extraction_path)
      print(e)

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
   
