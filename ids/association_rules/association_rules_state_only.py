import json
import statistics
import sys
from ids.association_rules.JSONHelper import JSONHelper, remap_keys, to_recursive_set
import ipal_iids.settings as settings
from ids.ids import MetaIDS
import pandas as pd
from mlxtend.frequent_patterns import association_rules, fpgrowth
from sklearn.cluster import KMeans
from collections import Counter

NX_LABEL = sys.maxsize


class AssociationRulesStateOnly(MetaIDS):
    _name = "association-rules-state-only"
    _description = "IDS based on AssociationRules"
    _requires = ["train.ipal", "live.ipal"]
    _modelfile = "model"
    _association_rules_default_settings = {
        "itemset_size": 5,  # the size of each itemset
        "min_support": 0.2,
        "min_confidence": 0.6,
        "num_process_value_clusters": 3
    }
    _supports_preprocessor = False

    def __init__(self, name=None):
        super().__init__(name=name)
        self._name = name
        self.classes = set()  # stores all classes produced by the classifier during training
        self.process_value_labels = set()  # stores all labels of process values
        self.frequent_itemsets = []
        self.association_rules = []
        self.rule_time_delays = {}
        self.kmeans = KMeans(n_clusters=self.settings["num_process_value_clusters"])

        self.last_packets = []
        self.last_live_packets = []
        self.last_live_timestamps = []
        self._add_default_settings(self._association_rules_default_settings)

    def get_process_value_class(self, process_value_dict):
        if len(process_value_dict.keys()) == 0:
            return "no-pvs"
        elif None in process_value_dict.values():
            return "request" + str(list(process_value_dict.keys()))
        else:
            current_data_point = []
            for label in self.process_value_labels:
                if label in process_value_dict.keys():
                    current_data_point.append(process_value_dict[label])
                else:
                    print("Hier ist was falsch")
            return f"Class_{self.kmeans.predict([current_data_point])[0]}"
            # return f"Class-{self.kmeans.predict([tuple(process_value_dict.values())])[0]}"

    # returns the classification label of the input message
    # if add_class is True additionally adds the label to the list of all known labels
    def classify(self, message, add_class=False):
        # classify messages by process_values
        process_value_class = self.get_process_value_class(message["state"])
        label = process_value_class

        if add_class:
            self.classes.add(label)

        return label

    def train(self, ipal=None, state=None):
        print("Training started")

        print("Starting Preprocessing")
        # In the preprocessing step bins for classifying the process values of packets are computed
        self.do_preprocessing(ipal)
        print("Finished Preprocessing")

        last_n_packets = []
        num_seen_packets = 0

        all_windows = {}

        test_all_labels = []
        with self._open_file(ipal) as f:
            for line in f.readlines():  # generate the sliding windows
                current_packet = json.loads(line)
                current_packet_label = self.classify(current_packet, add_class=True)
                test_all_labels.append(current_packet_label)

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
        for x in self.classes:
            print(x)
        print(Counter(test_all_labels))

        # and the association rules
        print("Computing Association Rules")
        self.association_rules = association_rules(self.frequent_itemsets, metric='confidence',
                                                   min_threshold=self.settings["min_confidence"])
        print(self.association_rules.to_string())

        print("Finished Training")

    # uses k-means clustering to generate bins for process values
    # packets with process values in the same cluster receive the same label for the process values
    # each label of a process_value corresponds to one dimension for the clustering
    def do_preprocessing(self, ipal):
        # iterates over all packets to find all possible process labels
        with self._open_file(ipal) as f:
            for line in f.readlines():
                self.process_value_labels.update(json.loads(line)["state"].keys())

        # compute data points for clustering, i.e., tuples of process values
        data_points = []
        with self._open_file(ipal) as f:
            # data_points = [json.loads(line)[data_label] for line in f.readlines()]

            for line in f.readlines():
                current_data_dict = json.loads(line)["state"]
                current_data_point = []

                # todo: adjust for when some packets do not contain all possible data points
                if len(current_data_dict) > 0 and None not in current_data_dict.values():
                    for label in self.process_value_labels:
                        if label in current_data_dict.keys():
                            current_data_point.append(current_data_dict[label])
                        else:
                            print("Non-existent label found")
                            current_data_point.append(NX_LABEL - 1)
                    data_points.append(current_data_point)

        print(data_points[0], data_points[-1])

        # compute the clustering
        # self.kmeans.fit_predict(data_points)
        predictions = self.kmeans.fit_predict(data_points)
        print(Counter(predictions))
        print([[float(x) for x in y] for y in self.kmeans.cluster_centers_])

    def new_ipal_msg(self, msg):
        self.last_live_packets.append(self.classify(msg))
        self.last_live_timestamps.append(msg["timestamp"])

        if len(self.last_live_packets) > self.settings["itemset_size"]:
            self.last_live_packets.pop(0)
            self.last_live_timestamps.pop(0)

        # fill the buffer with packets until there are enough
        elif len(self.last_live_packets) < self.settings["itemset_size"]:
            return None, 0

        for i in range(len(self.association_rules)):
            antecedent = frozenset(self.association_rules.loc[i, "antecedents"])
            consequent = frozenset(self.association_rules.loc[i, "consequents"])

            test_set = set(self.last_live_packets)

            if antecedent.issubset(test_set):
                if not consequent.issubset(test_set):  # if the consequent does not appear at all
                    return True, f"The rule{antecedent} => {consequent} was violated with confidence {self.association_rules.loc[i, 'confidence']}"
        return False, 0

    # todo: find a way to serialize k_means object
    # def save_trained_model(self):
    #     if self.settings["model-file"] is None:
    #         return False
    #
    #     model = {
    #         "_name": self._name,
    #         "settings": self.settings,
    #         "classes": self.classes,
    #         "itemsets": self.frequent_itemsets.to_json(),
    #         "association_rules": self.association_rules.to_json(),
    #         "rule_time_delays": remap_keys(self.rule_time_delays),
    #     }
    #
    #     with self._open_file(self._resolve_model_file_path(), mode="wt") as f:
    #         f.write(json.dumps(model, indent=4, cls=JSONHelper) + "\n")
    #
    #     return True

    # def load_trained_model(self):
    #     if self.settings["model-file"] is None:
    #         return False
    #
    #     try:  # Open model file
    #         with self._open_file(self._resolve_model_file_path(), mode="rt") as f:
    #             model = json.load(f)
    #     except FileNotFoundError:
    #         settings.logger.info(
    #             "Model file {} not found.".format(str(self._resolve_model_file_path()))
    #         )
    #         return False
    #
    #     # Load model
    #     assert self._name == model["_name"]
    #     self.settings = model["settings"]
    #     self.classes = set(model["classes"])
    #     self.frequent_itemsets = pd.read_json(model["itemsets"]) # todo: convert the lists in this FD to tuples
    #     self.association_rules = pd.read_json(model["association_rules"]) # todo: convert the lists in this FD to tuples
    #     self.rule_time_delays = to_recursive_set(model["rule_time_delays"])
    #     return True
