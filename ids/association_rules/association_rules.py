import json
from ids.ids import MetaIDS
import pandas as pd
from mlxtend.frequent_patterns import apriori, association_rules


class AssociationRules(MetaIDS):
    _name = "association-rules"
    _description = "IDS based on AssociationRules"
    _requires = ["train.ipal"]
    _modelfile = "model"
    _association_rules_default_settings = {
        "itemset_size": 5,  # the size of each itemset
        "min_support": 0.2,
        "min_confidence": 0.8
    }
    _supports_preprocessor = False

    def __init__(self, name=None):
        super().__init__(name=name)
        self._name = name
        self.last_packets = []
        self.classes = set()  # stores all classes produced by the classifier during training
        self.frequent_itemsets = []
        self.association_rules = []
        self.last_live_packets = []
        self._add_default_settings(self._association_rules_default_settings)

    # returns the classification label of the input message
    # if add_class is True additionally adds the label to the list of all known labels
    def classify(self, message, add_class=False):
        protocol = message["protocol"]
        m_type = message["type"]
        activity = message["activity"]

        label = f"{protocol}-{m_type}-{activity}"
        if add_class:
            self.classes.add(label)
        return label

    def train(self, ipal=None, state=None):
        last_n_packets = []
        n_windows = pd.DataFrame()

        with self._open_file(ipal) as f:
            for line in f.readlines():
                current_packet = json.loads(line)
                current_packet_label = self.classify(current_packet, add_class=True)

                # append the latest packet if the queue contains n-1 packets
                last_n_packets.append(current_packet_label)

                # if the buffer is not full yet, skip and add more packets
                if len(last_n_packets) < self.settings["itemset_size"]:
                    continue

                # add the current sliding window to our database
                n_windows = pd.concat([n_windows, pd.DataFrame([last_n_packets])])

                # pop the first item so that we can move the window by one element
                last_n_packets.pop(0)

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
        # and the association rules
        self.association_rules = association_rules(self.frequent_itemsets, metric='confidence', min_threshold=self.settings["min_confidence"])
        print(self.association_rules)

    def new_ipal_msg(self, msg):
        self.last_live_packets.append(self.classify(msg))

        # fill the buffer with packets until there are enough
        if len(self.last_live_packets) < self.settings["itemset_size"]:
            return None, 0

        for rule in self.association_rules:
            if rule["antecedents"].issubset(self.last_live_packets) \
                    and not rule["consequents"].issubset(self.last_live_packets):
                return True, f"The rule{rule['antecedents']} => {rule['consequents']} with confidence {rule['confidence']} was violated"

        return None, 0
