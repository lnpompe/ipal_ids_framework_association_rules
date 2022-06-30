from ids.ids import MetaIDS


def classify(message):
    protocol = message["protocol"]
    m_type = message["type"]
    activity = message["activity"]

    label = f"{protocol}-{m_type}-{activity}"
    return label


class AssociationRules(MetaIDS):
    _name = "AssociationRules"
    _description = "IDS based on AssociationRules"
    _requires = ["train.ipal", "live.ipal"]
    _modelfile = "model"
    _supports_preprocessor = False

    def __init__(self, itemset_size, name=None):
        super().__init__(name=name)
        self._name = name
        self.n = itemset_size
        self.last_packets = []
        self.classes = (
            []
        )  # stores all classes produced by the classifier during training

    def train(self, ipal=None, state=None):
        pass

    def new_ipal_msg(self, msg):
        pass
