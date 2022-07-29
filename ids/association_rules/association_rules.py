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
        "min_confidence": 0.6,
        "process_value_bin_size": 100,
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
        self.last_live_timestamps = []
        self.rule_time_delays = {}
        self._add_default_settings(self._association_rules_default_settings)

    # helper method for the classifier
    # takes as input the value of some register
    # returns the bin in which the value falls into
    # if the value is not an integer, the original value is not a number
    def get_bin(self, value):
        if isinstance(value, int) or isinstance(value, float):
            return int(value) - (int(value) % self.settings["process_value_bin_size"])
            # Alternatively, return the sign of value instead of its bin
            # if value < 0:
            #     return -1
            # if value == 0:
            #     return 0
            # if value > 0:
            #     return 1
        else:
            return value

    # returns the classification label of the input message
    # if add_class is True additionally adds the label to the list of all known labels
    def classify(self, message, add_class=False):
        protocol = message["protocol"]
        m_type = message["type"]
        activity = message["activity"]
        src = message["src"].split(":")[0].replace(".", ":")
        dest = message["dest"].split(":")[0].replace(".", ":")

        # classify messages by process_values
        # put values into bins of size process_value_bin_size (see settings)
        process_values = message["data"]
        for key, value in process_values.items():
            process_values[key] = self.get_bin(value)
        process_values = str(process_values).replace("'", "").replace(".", ":")

        label = f"{protocol}-{m_type}-{activity}-{src}-{dest}-{process_values}"
        if add_class:
            self.classes.add(label)
        return label

    def train(self, ipal=None, state=None):
        last_n_packets = []
        n_windows = pd.DataFrame()

        with self._open_file(ipal) as f:
            for line in f.readlines():  # generate the sliding windows
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

        # transforms n_windows from multisets to normal sets
        n_windows = n_windows.astype('bool')

        # compute the frequent itemsets
        self.frequent_itemsets = apriori(n_windows, self.settings["min_support"], use_colnames=True)
        # and the association rules
        self.association_rules = association_rules(self.frequent_itemsets, metric='confidence', min_threshold=self.settings["min_confidence"])

        # for x in self.classes:
        #     print(x, "\n")
        # print(self.association_rules.to_string())

        print("Starting Postprocessing")
        self.do_postprocessing(ipal)
        print("Finished Training")

    # iterates over the whole training data once again to generate the dictionary rule_time_delays
    # which in the end contains for each rule (antecedent, consequent)
    # the min and max time between the timestamp of the last antecedent and the last consequent packet
    def do_postprocessing(self, ipal):
        last_n_packets = []
        last_n_timestamps = []

        for i in range(len(self.association_rules)):
            antecedent = self.association_rules.loc[i, "antecedents"]
            consequent = self.association_rules.loc[i, "consequents"]
            self.rule_time_delays[(antecedent, consequent)] = []

        with self._open_file(ipal) as f:
            for line in f.readlines():
                current_packet = json.loads(line)
                current_packet_label = self.classify(current_packet)
                current_packet_timestamp = current_packet["timestamp"]

                # append the latest packet if the queue contains n-1 packets
                last_n_packets.append(current_packet_label)
                last_n_timestamps.append(current_packet_timestamp)

                # if the buffer is not full yet, skip and add more packets
                if len(last_n_packets) < self.settings["itemset_size"]:
                    continue

                for i in range(len(self.association_rules)):
                    antecedent = self.association_rules.loc[i, "antecedents"]
                    consequent = self.association_rules.loc[i, "consequents"]
                    test_set = set(last_n_packets)

                    # for each association rule calc_delay will contain a list of all delays between antecedent and consequent
                    if antecedent.issubset(test_set) and consequent.issubset(test_set):
                        self.rule_time_delays[(antecedent, consequent)].append(
                            self.calc_delay(last_n_packets, last_n_timestamps, antecedent, consequent)
                        )

                # pop the first item so that we can move the window by one element
                last_n_packets.pop(0)
                last_n_timestamps.pop(0)

        for rule, delays in self.rule_time_delays.items():
            self.rule_time_delays[rule] = (min(delays), max(delays))
            print(rule, self.rule_time_delays[rule])

    def calc_delay(self, last_n_packets, last_n_timestamps, antecedent, consequent):
        # last timestamp of the packets of the antecedent
        antecedent_time = -1
        # last timestamp of the packets of the consequent
        consequent_time = -1

        for cur_label, cur_timestamp in zip(last_n_packets, last_n_timestamps):
            if cur_label in antecedent and cur_timestamp > antecedent_time:
                antecedent_time = cur_timestamp

            if cur_label in consequent and cur_timestamp > consequent_time:
                consequent_time = cur_timestamp

        return antecedent_time - consequent_time

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

            antecedent = self.association_rules.loc[i, "antecedents"]
            consequent = self.association_rules.loc[i, "consequents"]

            test_set = set(self.last_live_packets)

            if antecedent.issubset(test_set):
                if not consequent.issubset(test_set):  # if the consequent does not appear at all
                    print(f"The rule {antecedent} => {consequent} was violated with confidence {self.association_rules.loc[i, 'confidence']}")
                    return True, f"The rule{antecedent} => {consequent} was violated with confidence {self.association_rules.loc[i, 'confidence']}"

                else:  # if the delay between antecedent and consequent is
                    current_delay = self.calc_delay(self.last_live_packets, self.last_live_timestamps, antecedent, consequent)
                    min_delay, max_delay = self.rule_time_delays[(antecedent, consequent)]
                    if not min_delay <= current_delay <= max_delay:
                        print(f"The delay between antecedent {antecedent} and consequent {consequent} was too low/high. Min: {min_delay}, Actual: {current_delay}, Max: {max_delay}.")
                        return True, f"The delay between antecedent {antecedent} and consequent {consequent} was too low/high. Min: {min_delay}, Actual: {current_delay}, Max: {max_delay}."
        return None, 0

    def print_attributes(self):
        with open("output.txt", 'w') as f:
            f.write(self.frequent_itemsets.to_string())
            f.write('\n ASSOCIATION RULES \n')
            f.write(self.association_rules.to_string())

