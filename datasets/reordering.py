import pandas as pd
import numpy as np
import sys


PLACEHOLDER = "placeholder123"

in_file = sys.argv[1] #'GRFICS/30min/normal_30min_01_copy2.ipal'
out_file = sys.argv[2] #'GRFICS/attacks/normal_30_01_removed.ipal'
diff_file = sys.argv[3] #'GRFICS/attacks/normal_30_01_removed_diff.json'

df = pd.read_json(in_file, lines=True)

df.set_index('id')

# reordering
ids_to_shuffle = np.random.randint(0, len(df), int(0.001*len(df)))
sample = df
window_size = 10
for i in ids_to_shuffle:

    # print("Before:")
    if i+window_size < len(sample):
        temp_row = sample.iloc[i]
        sample.iloc[i] = sample.iloc[i+window_size]
        sample.iloc[i+window_size] = temp_row

sample.to_json(out_file, orient='records', lines=True)

diff = pd.DataFrame(ids_to_shuffle, columns=['id'])
diff.to_json(diff_file, orient='records', lines=True)




