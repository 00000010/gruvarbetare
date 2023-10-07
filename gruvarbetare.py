#!/usr/bin/env python3

# TODO: Research packed binaries: what they look like, 
import argparse
from pathlib import Path
import magic

def identify(f):
#  while (byte := f.read(1)):
#    print(byte)
  return

def main():
  # Parse program args
  parser = argparse.ArgumentParser(prog="gruvarbetare")
  parser.add_argument("-f", "--file", dest="filename", help="file to unpack", metavar="FILE")
  args = parser.parse_args()

  # Attempt to manipulate file
  f = None
  if args.filename:
    try:
      print(magic.from_file(args.filename))
      print(magic.from_file(args.filename, mime = True))
      with open(args.filename, 'rb') as f:
        identify(f)
    except FileNotFoundError:
      print("Error: file does not exist.")
      return

if __name__ == '__main__':
  main()
