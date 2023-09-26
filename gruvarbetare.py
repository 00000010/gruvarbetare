#!/usr/bin/env python3

import argparse
from pathlib import Path

def main():
  parser = argparse.ArgumentParser(prog="gruvarbetare")
  parser.add_argument("-f", "--file", dest="filename", help="file to unpack", metavar="FILE")
  args = parser.parse_args()

  if args.filename:
    try:
      f = open(args.filename, 'r')
    except FileNotFoundError:
      print("Error: file does not exist.")

if __name__ == '__main__':
  main()
