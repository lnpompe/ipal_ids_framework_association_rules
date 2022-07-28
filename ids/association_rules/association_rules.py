import json
from ids.ids import MetaIDS
import pandas as pd
from mlxtend.frequent_patterns import apriori, association_rules


class AssociationRules(MetaIDS):
    _name = "association-rules"
    _description = "IDS based on AssociationRules"
    _requires = ["train.ipal", "live.ipal"]
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
        src = message["src"].split(":")[0].replace(".", ":")
        dest = message["dest"].split(":")[0].replace(".", ":")

        label = f"{protocol}-{m_type}-{activity}-{src}-{dest}"
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
        # print(n_windows)

        # transforms n_windows from multisets to normal sets
        n_windows = n_windows.astype('bool')
        # print(n_windows)

        # compute the frequent itemsets
        self.frequent_itemsets = apriori(n_windows, self.settings["min_support"], use_colnames=True)
        # print(self.frequent_itemsets)
        # and the association rules
        self.association_rules = association_rules(self.frequent_itemsets, metric='confidence', min_threshold=self.settings["min_confidence"])
        # self.association_rules['antecedents'] = self.association_rules['antecedents'].apply(lambda x: list(x)[0]).astype("unicode")
        # self.association_rules['consequents'] = self.association_rules['consequents'].apply(lambda x: list(x)[0]).astype("unicode")
        # print(self.association_rules.to_string())
        # print(self.classes)

    def new_ipal_msg(self, msg):
        self.last_live_packets.append(self.classify(msg))

        if len(self.last_live_packets) > self.settings["itemset_size"]:
            self.last_live_packets.pop(0)
        # fill the buffer with packets until there are enough
        elif len(self.last_live_packets) < self.settings["itemset_size"]:
            return None, 0

        for i in range(len(self.association_rules)):

            antecedent = self.association_rules.loc[i, "antecedents"]
            consequent = self.association_rules.loc[i, "consequents"]

            test_set = set(self.last_live_packets)

            if antecedent.issubset(test_set) \
                    and not consequent.issubset(test_set):
                print(f"The rule {antecedent} => {consequent} was violated with confidence {self.association_rules.loc[i, 'confidence']}")
                return True, f"The rule{antecedent} => {consequent} was violated with confidence {self.association_rules.loc[i, 'confidence']}" #  {rule['confidence']}

        return None, 0

    def print_attributes(self):
        with open("output.txt", 'w') as f:
            f.write(self.frequent_itemsets.to_string())
            f.write('\n ASSOCIATION RULES \n')
            f.write(self.association_rules.to_string())

