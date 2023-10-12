#!/usr/bin/env python3

# TODO: What is the difference between an unknown packer and a random program?
#   Need to analyze behavior of program (angr)

# For parsing commandline args
import argparse
from pathlib import Path
# For binary first guesses
import magic
# For creating/reading yara rules
import yara
# Main binary analysis engine
import angr

import os

# Path to gruvarbetare
dir_path = os.path.dirname(os.path.realpath(__file__))

def analyze(filename):
  # Angr setup
  proj = angr.Project(filename, auto_load_libs=False)
  ss = proj.factory.entry_state()
  simgr = proj.factory.simulation_manager(ss)

  generate_data(proj)
  return

# TODO: move this into a separate python script
def generate_data(angr_proj):
  obj = proj.loader.main_object

  # Get basic info about the ELF
  min_addr = obj.min_addr
  max_addr = obj.max_addr
  segments = obj.segments
  segments_size = [0]*len(segments)
  for i in range(len(segments)):
    segments_size[i] = segments[i].memsize
  shared_objs = [i for i in proj.loader.shared_objects]
  requested_names = proj.loader.requested_names

  path_analysis(angr_proj)
  return

def path_analysis(angr_proj):
  return

def more(filename):
  custom_rules = yara.compile(filepath=dir_path + '/custom_packer.yar')
  matches = custom_rules.match(filename)
  if matches:
    print("Matches custom rules: ")
    for m in matches:
      print(m)
  else:
    print("Program does not match any signatures.")
    # Add sample to collection to analyze
    with open(filename, "rb") as in_f:
      content = in_f.read()
    # TODO: Make OS-independent (os.path.basename)
    with open(dir_path + "/sample_dumps/" + os.path.basename(filename) + ".dump", "w") as out_f:
      out_f.write(content.hex())
    analyze(filename)
  return

def main():
  # Parse program args
  parser = argparse.ArgumentParser(prog="gruvarbetare")
  parser.add_argument("-f", "--file", dest="filename", help="file to unpack", metavar="FILE")
  args = parser.parse_args()

  # Compile Yara rules
  rules = yara.compile(filepath=dir_path + '/packer.yar')

  # Attempt to manipulate file
  f = None
  if args.filename:
    try:
      print("First guess: " + magic.from_file(args.filename))
      matches = []
      with open(args.filename, 'rb') as f:
        matches = rules.match(args.filename)
      if matches:
        print("Matches static rules: ")
        for m in matches:
          print(m)
      else:
        more(args.filename)
        print(matches)
        identify(f)
    except FileNotFoundError:
      print("Error: file does not exist.")
      return

if __name__ == '__main__':
  main()
