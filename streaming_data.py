from pysad.utils import PandasStreamer
import pandas as pd

data = pd.read_csv('./test.csv')

streamer = PandasStreamer()

for s in streamer.iter(data):
    print(s)