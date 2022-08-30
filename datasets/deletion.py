import pandas as pd
import sys
import numpy as np
PLACEHOLDER = "placeholder123"

in_file = sys.argv[1] #'GRFICS/30min/normal_30min_01_copy2.ipal'
out_file = sys.argv[2] #'GRFICS/attacks/normal_30_01_removed.ipal'
diff_file = sys.argv[3] #'GRFICS/attacks/normal_30_01_removed_diff.json'
# packet removal
#

df = pd.read_json(in_file, lines=True)
df.reset_index(drop=True)
df.set_index('id')

sample = df.sample(frac=0.9)
sample = sample.sort_index()

diff = pd.concat([df, sample]).drop_duplicates(subset=['id'], keep=False)
diff.reset_index(drop=True)
diff.set_index('id')
diff["start"] = diff[PLACEHOLDER]
diff["end"] = diff[PLACEHOLDER]

sample.to_json(out_file, orient='records', lines=True)
diff.to_json(diff_file, orient='records', indent=2)
