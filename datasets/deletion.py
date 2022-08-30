import pandas as pd
import numpy as np

in_file = 'normal_30_02.ipal'
out_file = './normal_30_02_removed.ipal'
diff_file = './normal_30_02_removed_diff.json'
# packet removal
#
df = pd.read_json(in_file, lines=True)
df['timestamp'] = df['timestamp'].astype('float')
df.reset_index(drop=True)
df.set_index('id')
print(type(df['timestamp'][1]))
sample = df.sample(frac=0.9)
sample = sample.sort_index()
print(sample['timestamp'])

diff = pd.concat([df, sample]).drop_duplicates(subset=['id'], keep=False)
diff.reset_index(drop=True)
diff.set_index('id')
print(diff['timestamp'])

diff["start"] = diff["timestamp"]
diff["end"] = diff["timestamp"]

sample.to_json(out_file, orient='records', lines=True)
diff.to_json(diff_file, orient='records', line=True)
