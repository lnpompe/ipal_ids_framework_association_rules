import pandas as pd
import numpy as np

# packet removal
#
df = pd.read_json('normal_15.ipal', lines=True)
df.set_index('id')
sample = df.sample(frac=0.9, random_state=690537191)
diff = pd.concat([df, sample]).drop_duplicates(subset=['id'], keep=False)
# print(df.columns)
# print(df)
# print(diff)
# print(sample)
sample.to_json('./normal_15_removed.ipal', orient='index')
diff.to_json('./normal_15_removed_diff.ipal', orient='index')


