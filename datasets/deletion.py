import pandas as pd
import numpy as np

in_file = 'normal_30_02.ipal'
out_file = './normal_30_02_removed.ipal'
diff_file = './normal_30_02_removed_diff.json'
# packet removal
#
df = pd.read_json(in_file, lines=True)
df.reset_index(drop=True)
df.set_index('id')
sample = df.sample(frac=0.9, random_state=690537191)
diff = pd.concat([df, sample]).drop_duplicates(subset=['id'], keep=False)
diff.reset_index(drop=True)
diff.set_index('id')
diff["start"] = diff["timestamp"]
diff["end"] = diff["timestamp"]


sample.to_json(out_file, orient='records', lines=True)
diff.to_json(diff_file, orient='records', indent=2)

