import pandas as pd
import os

# TODO: Ensure no duplicate hashes read in given updated full.csv
# Read in all hashes retrieved from bazaar.abuse.ch
def main():
  csv = 'full.csv'
  data_df = pd.read_csv(csv, usecols=[1], skiprows=8, engine='c')
  hashes = data_df['sha256_hash'][:-1]
  with open('./all_hashes.txt', 'a') as all_hashes:
    for h in hashes:
      try:
        all_hashes.write(h + '\n')
      except:
        print("Couldn't write: " + str(h))
#  os.remove(csv)
  return

if __name__ == '__main__':
  main()
