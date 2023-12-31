import pandas as pd
import requests
from os import listdir
from os.path import isfile, join
from process_module import process_module

def get_hashes(processed_hashes_path):
  hashes = set()
  try:
    with open(processed_hashes_path, 'r') as processed_hashes_file:
      for line in processed_hashes_file:
        hashes.add(processed_hashes_file.readline().strip())
  except FileNotFoundError:
    return set()
  return hashes

def main():
  print("Reading in hashes...")
  all_hashes = get_hashes('./all_hashes.txt')
  print("hash count: " + str(len(all_hashes)))
  processed_hashes = get_hashes('./processed_hashes.txt')
  print("Done.")
  api_url = 'https://mb-api.abuse.ch/api/v1/'
  params = { "query": "get_file", "sha256_hash": "" }
  samplesPath = "./downloaded"

  count = 0 # keep track of number of processed hashes
  print("Processing 100 hashes...")

  # Open file for keeping track of processed hashes
  with open('processed_hashes.txt', 'a') as processed_hashes_file:
    # Go through each hash in sample list gathered from bazaar.abuse.ch
    for h in all_hashes:
      # Do not process if sample already ingested
      if h in processed_hashes:
        continue
      
      # Download file according to hash to the downloaded folder
      params["sha256_hash"] = h
      try:
        response = requests.post(api_url, data=params)
      except requests.ConnectionError:
        print("Failed to download file. Are you connected to the Internet?")
        return
      data = response.content
      # TODO: Retry if response.ok not true
      with open('./downloaded/' + h + '.zip', 'wb') as s:
        s.write(data)

      # Add to processed samples list
      processed_hashes.add(h)
      processed_hashes_file.write(h + "\n")

      # If 100 sample zip files have been downloaded, pause downloading to save on space and process them
      if count > 100:
        # Also ask user to disconnect from the internet, for safety while processing malware samples
        print("Pausing. Please disconnect from the internet to continue processing.")
        userInput = input("Type 'disconnected' once you have done so.\n")
        while userInput != 'disconnected':
          userInput = input("Type 'disconnected' once you have done so.\n")

        print("Processing downloaded zip files...")

        # Unzip and add sample data using process
        for zippedFile in [f for f in listdir(samplesPath) if isfile(join(samplesPath, f))]:
          process_module(samplesPath + "/" + zippedFile, '../sample_data.csv')
          
        print("Done.")

        # Continue downloading samples
        print("Processing done. Please connect to the internet to continue.")
        userInput = input("Type 'connected' once you have done so.\n")
        while userInput != 'connected':
          userInput = input("Type 'connected' once you have done so.\n")

        count = 0
      
      count = count + 1
  return  

if __name__ == '__main__':
  main()
