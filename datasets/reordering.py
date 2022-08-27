import pandas as pd
import numpy as np

df = pd.read_json('normal_15.ipal', lines=True)

df.set_index('id')

# reordering
ids_to_shuffle = np.random.randint(0, len(df), int(0.1*len(df)))
sample = df
window_size = 10
for i in ids_to_shuffle:

    # print("Before:")
    if i+window_size < len(sample):
        temp_row = sample.iloc[i]
        sample.iloc[i] = sample.iloc[i+window_size]
        sample.iloc[i+window_size] = temp_row

sample.to_json('./normal_15_reordered.ipal', orient='index')
diff = pd.DataFrame(ids_to_shuffle, columns=['id'])
diff.to_json('./diff_15_reordered.ipal', orient='index')




