import pandas as pd

data_csv = "../known_samples.csv"
data_df = pd.read_csv(data_csv, sep=';')

# Print dataset info
#data_df.info()

# Describe the data
#print(data_df.describe())

print(data_df['Segments'])
