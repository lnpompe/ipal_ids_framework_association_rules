import json
import statistics
import sys
from ids.ids import MetaIDS
import pandas as pd
from mlxtend.frequent_patterns import association_rules, fpgrowth
from sklearn.cluster import KMeans
from collections import Counter

NX_LABEL = sys.maxsize
NUM_ITEMS_TOTAL = "416800"

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
        self.variances = []
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

    def get_process_value_class(self, process_value_dict):
        current_data_point = list(process_value_dict.values())
        # if len(process_value_dict.keys()) == 0:
        #     return "no-pvs"
        # elif None in process_value_dict.values():
        #     return "request" + str(list(process_value_dict.keys()))
        # else:
        #     current_data_point = []
        #     for label in self.process_value_labels:
        #         if label in process_value_dict.keys():
        #             current_data_point.append(process_value_dict[label])
        #         else:
        #             print("Hier ist was falsch")
        return int(self.kmeans.predict([current_data_point])[0])
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

        cnt = Counter()
        with self._open_file(ipal) as f:
            for line in f.readlines():  # generate the sliding windows
                current_packet = json.loads(line)
                current_packet_label = self.classify(current_packet, add_class=True)
                cnt.update([current_packet_label])
                # print(cnt, str(cnt.total()) + " / " + NUM_ITEMS_TOTAL)

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
    def do_preprocessing(self, ipal):
        # iterates over all packets to find all possible process labels
        with self._open_file(ipal) as f:
            for line in f.readlines():
                self.process_value_labels.update(json.loads(line)["state"].keys())

        # compute data points for clustering, i.e., tuples of process values
        data_points = []
        with self._open_file(ipal) as f:

            for line in f.readlines():
                current_data_point = list(json.loads(line)["state"].values())

                data_points.append(current_data_point)

        # compute the clustering
        self.kmeans.fit(data_points)
        # predictions = self.kmeans.fit_predict(data_points)
        # print(predictions)
        # predictions_by_class = []
        # self.variances = []
        # for x in range(self.kmeans.n_clusters):
        #     predictions_by_class.append([])
        #     self.variances.append([])
        #
        # for datapoint, prediction in zip(data_points, predictions):
        #     predictions_by_class[prediction].append(datapoint)


        # for x in range(self.kmeans.n_clusters):
        #     for y in range(len(data_points[0])):
        #         self.variances[x].append(statistics.stdev([value[y] for value in predictions_by_class[x]]))
                # print(x, y)
                # print(statistics.stdev([value[y] for value in predictions_by_class[x]], self.kmeans.cluster_centers_[x][y]))

        # distances = [abs(data_point - mean_point) - stdev for (data_point, mean_point, stdev) in zip(data_points[0], self.kmeans.cluster_centers_[0], self.variances[0])]
        # print(distances)
        # print(len(data_points[0]), data_points[0])
        # print(len(self.kmeans.cluster_centers_[0]), self.kmeans.cluster_centers_[0])
        # print(len(self.variances[0]), self.variances[0])
        # exit()

    def new_ipal_msg(self, msg):
        current_label = self.classify(msg)
        self.last_live_packets.append(current_label)


        # Check distance from mean center
        # distances = [10 * stdev - abs(data_point - mean_point) for (data_point, mean_point, stdev) in zip(list(msg["state"].values()), self.kmeans.cluster_centers_[current_label], self.variances[current_label])]
        # if any(d < 0 for d in distances):
        #     return True, f"Distance to cluster center was larger than standard deviation"


        if len(self.last_live_packets) > self.settings["itemset_size"]:
            self.last_live_packets.pop(0)

        # fill the buffer with packets until there are enough
        elif len(self.last_live_packets) < self.settings["itemset_size"]:
            return None, 0

        last_live_packets_set = set(self.last_live_packets)
        # print(last_live_packets_set)

        if len(last_live_packets_set) > 1:
            for i in range(len(self.association_rules)):
                antecedent = frozenset(self.association_rules.loc[i, "antecedents"])
                consequent = frozenset(self.association_rules.loc[i, "consequents"])

                test_set = set(self.last_live_packets)

                if antecedent.issubset(test_set):
                    if not consequent.issubset(test_set):  # if the consequent does not appear at all
                        return True, f"The rule{antecedent} => {consequent} was violated with confidence {self.association_rules.loc[i, 'confidence']}"
        return False, 0
