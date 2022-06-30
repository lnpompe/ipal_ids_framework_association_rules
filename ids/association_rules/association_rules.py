import json
from ids.ids import MetaIDS
import pandas as pd
from mlxtend.frequent_patterns import apriori


class AssociationRules(MetaIDS):
    _name = "association-rules"
    _description = "IDS based on AssociationRules"
    _requires = ["train.ipal"]
    _modelfile = "model"
    _association_rules_default_settings = {
        "itemset_size": 5,  # the size of each itemset
        "min_support": 0.3,
        "min_confidence": 1.0
    }
    _supports_preprocessor = False

    def __init__(self, name=None):
        super().__init__(name=name)
        self._name = name
        self.last_packets = []
        self.classes = set()  # stores all classes produced by the classifier during training
        self.frequent_itemsets = []
        self._add_default_settings(self._association_rules_default_settings)

    # returns the classification label of the input message
    # additionally adds the label to the list of all known labels
    def classify(self, message):
        protocol = message["protocol"]
        m_type = message["type"]
        activity = message["activity"]

        label = f"{protocol}-{m_type}-{activity}"
        self.classes.add(label)
        return label

    def train(self, ipal=None, state=None):
        last_n_packets = []
        n_windows = pd.DataFrame()

        with self._open_file(ipal) as f:
            for line in f.readlines():
                current_packet = json.loads(line)
                current_packet_label = self.classify(current_packet)

                # fill buffer of last DEPTH messages
                if len(last_n_packets) < self.settings["itemset_size"] - 1:
                    last_n_packets.append(current_packet_label)
                    continue

                # append the latest packet if the queue contains n-1 packets
                last_n_packets.append(current_packet_label)

                # add the current sliding window to our database
                n_windows = pd.concat([n_windows, pd.DataFrame([last_n_packets])])

                # pop the first item so that we can move the window by one element
                last_n_packets.pop(0)
            # print(n_windows)

            # transforms n_windows to one-hot encoding multisets
            n_windows = pd.get_dummies(n_windows.astype(str))
            n_windows.columns = n_windows.columns.str.split('_').str[1].str.split('.').str[0]
            n_windows = n_windows.groupby(level=0, axis=1).sum()
            print(n_windows)

            # transforms n_windows from multisets to normal sets
            n_windows = n_windows.astype('bool')
            print(n_windows)

            # compute the frequent itemsets
            self.frequent_itemsets = apriori(n_windows, self.settings["min_support"], use_colnames=True)
            print(self.frequent_itemsets)

    def new_ipal_msg(self, msg):
        pass
