import json
from math import dist
from statistics import stdev
import sys
from typing import Iterable

from ids.ids import MetaIDS
import pandas as pd
from mlxtend.frequent_patterns import association_rules, fpgrowth
from sklearn.cluster import KMeans
from collections import Counter
from preprocessors.utils import get_all_preprocessors

NX_LABEL = sys.maxsize
NUM_ITEMS_TOTAL = "416800"


def _extract_features(msg):
    return list(msg["state"].values())


class AssociationRulesStateOnly(MetaIDS):
    _name = "association-rules-state-only"
    _description = "IDS based on AssociationRules"
    _requires = ["train.ipal", "live.ipal"]
    _modelfile = "model"
    _association_rules_default_settings = {
        "itemset_size": 1800,  # the size of each itemset
        "min_support": 0.2,
        "min_confidence": 1.0,
        "num_process_value_clusters": 12,
        "features": [],  # Feature list forwarded to the IDS after preprocessing
        "preprocessors": [],  # List of preprocessors applied to the data
        "allow-none": False,
    }
    _supports_preprocessor = True

    preprocessors = []

    def __init__(self, name=None):
        super().__init__(name=name)
        self.distances = []
        self._name = name
        self.classes = set()  # stores all classes produced by the classifier during training
        self.process_value_labels = set()  # stores all labels of process values
        self.frequent_itemsets = []
        self.association_rules = []
        self.rule_time_delays = {}
        self.kmeans = KMeans(n_clusters=self.settings["num_process_value_clusters"])

        self.last_packets = []
        self.last_live_packets = []
        self._add_default_settings(self._association_rules_default_settings)

        self.preprocessors = []
        self.features = []


    # returns the classification label of the input message
    # if add_class is True additionally adds the label to the list of all known labels
    def classify(self, message, add_class=False):
        # classify messages by process_values
        # process_value_class = int(self.kmeans.predict([_extract_features(message)])[0])
        process_value_class = int(self.kmeans.predict([message])[0])
        if add_class:
            self.classes.add(process_value_class)

        return process_value_class

    def classify_state(self, state, add_class=False):
        # classify messages by process_values
        # process_value_class = int(self.kmeans.predict([_extract_features(message)])[0])
        process_value_class = int(self.kmeans.predict([state])[0])
        if add_class:
            self.classes.add(process_value_class)

        return process_value_class

    def normalize_inputs(self, state):
        # Set features for preprocessor
        # with open(state) as infile:
        #     msg = json.loads(infile.readline())
        #     print(type(msg))
        #     print(msg.keys())
        #     print(msg["state"].keys())
        #     print(self.settings)
        #     self.settings["preprocessors"]["features"] = list(msg["state"].keys())

        # Build preprocessors from settings
        for pre in self.settings["preprocessors"]:
            apply = [f in pre["features"] for f in self.settings["features"]]
            self.preprocessors.append(get_all_preprocessors()[pre["method"]](apply))

        self.features = [f.split(";") for f in self.settings["features"]]

        events = []
        annotations = []
        timestamps = []

        # Load features from training file

        with self._open_file(state) as state_file:
            for msg in state_file.readlines():
                msg = json.loads(msg)
                state = _extract_features(msg)

                if None not in state or self.settings["allow-none"]:
                    events.append(state)
                    annotations.append(msg["malicious"])
                    timestamps.append(msg["timestamp"])

        # Train and apply preprocessors
        # print("Raw features: {}".format(events[0]))
        for pre in self.preprocessors:
            pre.fit(events)
            events = [pre.transform(e) for e in events]

            # Remove events, annotations and timestamps if event got removed
            events, annotations, timestamps = zip(
                *[
                    (e, a, t)
                    for e, a, t in zip(events, annotations, timestamps)
                    if e is not None
                ]
            )
            assert len(events) == len(annotations) == len(timestamps)
            # print("{} features: {}".format(pre._name, events[0]))

        events = [list(self.__flatten(e)) for e in events]

        for pre in self.preprocessors:
            pre.reset()  # reset preprocessors before going live

        return events

    def train(self, ipal=None, state=None):
        print("Training started")
        print("Fitting Mean-Preprocessor")
        states = self.normalize_inputs(ipal)
        print("First state: ", state[0])
        print("Starting Preprocessing")
        # In the preprocessing step bins for classifying the process values of packets are computed
        self.do_preprocessing(states)
        print("Finished Preprocessing")

        last_n_packets = []
        num_seen_packets = 0

        all_windows = {}

        # with self._open_file(ipal) as f:
        #     for line in f.readlines():  # generate the sliding windows
        for current_state in states:
            # current_packet = json.loads(line)
            current_packet_label = self.classify_state(current_state, add_class=True)

            # append the latest packet if the queue contains n-1 packets
            last_n_packets.append(current_packet_label)

            # if the buffer is not full yet, skip and add more packets
            if len(last_n_packets) < self.settings["itemset_size"]:
                continue

            # add the current sliding window to our database
            # current_window_dict = {label: [True] for label in last_n_packets}
            # all_windows.append(current_window_dict)
            for label in self.classes:  # todo: make compatible with new preprocessing
                if label not in all_windows:
                    all_windows[label] = [False] * num_seen_packets + [True]
                else:
                    all_windows[label].append(label in last_n_packets)

            num_seen_packets = num_seen_packets + 1

            # pop the first item so that we can move the window by one element
            last_n_packets.pop(0)

        print("Computing One-Hot Encoding")
        n_windows = pd.DataFrame(all_windows)

        # compute the frequent itemsets
        print("Computing Frequent Itemsets")
        self.frequent_itemsets = fpgrowth(n_windows, self.settings["min_support"], use_colnames=True)

        # and the association rules
        print("Computing Association Rules")
        self.association_rules = association_rules(self.frequent_itemsets, metric='confidence',
                                                   min_threshold=self.settings["min_confidence"])
        print(self.association_rules.to_string())

        print("Finished Training")

    # uses k-means clustering to generate bins for process values
    # packets with process values in the same cluster receive the same label for the process values
    # each label of a process_value corresponds to one dimension for the clustering
    def do_preprocessing(self, states):
        # compute data points for clustering, i.e., tuples of process values
        # data_points = []
        # with self._open_file(ipal) as f:

            # for line in f.readlines():
            #     current_data_point = list(json.loads(line)["state"].values())

                # data_points.append(current_data_point)

        # compute the clustering
        # self.kmeans.fit(states)
        predictions = self.kmeans.fit_predict(states)
        # print(predictions)

        # Create and fill arrays
        predictions_by_class = []
        self.distances = []
        for x in range(self.kmeans.n_clusters):
            predictions_by_class.append([])
            self.distances.append([])

        for datapoint, prediction in zip(states, predictions):
            predictions_by_class[prediction].append(datapoint)

        for kmeans_class in range(self.kmeans.n_clusters):
            print(f"Computing boundary for class {kmeans_class}")
            current_mean = self.kmeans.cluster_centers_[kmeans_class]
            for datapoint in predictions_by_class[kmeans_class]:
                self.distances[kmeans_class].append(dist(datapoint, current_mean))
            self.distances[kmeans_class] = max(self.distances[kmeans_class]) + stdev(self.distances[kmeans_class])
            print(self.distances[kmeans_class])

    def new_ipal_msg(self, msg):
        # Preprocess message
        state = _extract_features(msg)
        for pre in self.preprocessors:
            state = pre.transform(state)

        current_label = self.classify_state(state)
        self.last_live_packets.append(current_label)
        # print("Msg:", state)
        # print(f"{self.kmeans.cluster_centers_[current_label]}")

        # Check distance from mean center
        dist_closest_mean = dist(state, self.kmeans.cluster_centers_[current_label])
        if dist_closest_mean > self.distances[current_label]:
            print(f"Distance too large. Point: {state}, Center: {self.kmeans.cluster_centers_[current_label]}, Distance: {dist_closest_mean}, Allowed: {self.distances[current_label]}")
            return True, f"Distance to cluster center was too large. Was {dist_closest_mean}. Should be less than {self.distances[current_label]}"

        # fill the buffer with packets until there are enough
        if len(self.last_live_packets) > self.settings["itemset_size"]:
            self.last_live_packets.pop(0)
        elif len(self.last_live_packets) < self.settings["itemset_size"]:
            return None, 0

        last_live_packets_set = set(self.last_live_packets)

        if len(last_live_packets_set) > 1:
            for i in range(len(self.association_rules)):
                antecedent = frozenset(self.association_rules.loc[i, "antecedents"])
                consequent = frozenset(self.association_rules.loc[i, "consequents"])

                if antecedent.issubset(last_live_packets_set):
                    if not consequent.issubset(last_live_packets_set):  # if the consequent does not appear at all
                        return True, f"The rule{antecedent} => {consequent} was violated with confidence {self.association_rules.loc[i, 'confidence']}"
        return False, 0

    def __flatten(self, array):
        # https://stackoverflow.com/questions/2158395/flatten-an-irregular-list-of-lists?page=1&tab=votes#tab-top
        for el in array:
            if isinstance(el, Iterable) and not isinstance(el, (str, bytes)):
                yield from self.__flatten(el)
            else:
                yield el
