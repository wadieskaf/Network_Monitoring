# Import modules.
from sklearn.utils import shuffle
from pysad.evaluation import AUROCMetric
from pysad.models import xStream, IForestASD, KitNet
from pysad.utils import ArrayStreamer
from pysad.transform.postprocessing import RunningAveragePostprocessor
from pysad.transform.preprocessing import InstanceUnitNormScaler
from pysad.utils import Data, PandasStreamer
from tqdm import tqdm
import numpy as np
import pandas as pd
import time

# This example demonstrates the usage of the most modules in PySAD framework.
if __name__ == "__main__":
    np.random.seed(61)  # Fix random seed.

    # Get data to stream.
    df = pd.read_csv('test.csv', header=None, skiprows=1)
    df = df.fillna(0)
    print(df.head())

    # Necessary for KitNet, KitNet threw a key error when reading from a csv
    X = df.to_numpy()

    # Choose type of streamer based of the model
    # iterator = PandasStreamer(shuffle=False)
    iterator = ArrayStreamer(shuffle=False)


    # model = xStream()  # Init xStream anomaly detection model.

    # model = IForestASD(initial_window_X=df[:4096], window_size=2048)
    model = KitNet()
    model.fit(X[:5000])

    # need our own preprocessing as hexadecimals dont need zero variance but packet vs checksum length might
    preprocessor = InstanceUnitNormScaler()  # Init normalizer.
    postprocessor = RunningAveragePostprocessor(window_size=5)  # Init running average postprocessor.

    # Davies-Bouldin Index, Calinski-Harabasz Index, Silhouette Coefficient exist for clustering, none for anomaly detection
    # wrapped in BaseSKLearnMetric
    # no metrics I can see, AUC would be perfect if the dataset were labelled
    # maybe something else?
    auroc = AUROCMetric()  # Init area under receiver-operating- characteristics curve metric.

    for X in tqdm(iterator.iter(X[5000:])):  # Stream data.

        score = model.score_partial(X)
        print(score)
        # score = postprocessor.fit_transform_partial(score)  # Apply running averaging to the score.
        #
        # auroc.update(y, score)  # Update AUROC metric.

    # Output resulting AUROCS metric.
    # print("AUROC: ", auroc.get())