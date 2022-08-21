import json


# as JSON cannot parse dictionaries whose keys are tuples, the keys are transformed to lists
def remap_keys(mapping):
    return [{'key': k, 'value': v} for k, v in mapping.items()]


def to_recursive_set(obj):
    result = {}

    for key_value_pair in obj:
        result[key_value_pair["key"]] = key_value_pair["value"]

    return result


class JSONHelper(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set) or isinstance(obj, frozenset):
            return list(obj)
        return json.JSONEncoder.default(self, obj)
