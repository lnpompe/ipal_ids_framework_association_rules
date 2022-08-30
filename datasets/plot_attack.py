import matplotlib.pyplot as plt
import json

ATTACKFILE = 'normal_30_01_reordered_diff.json'
IN_FILE = '../IDS.ipal'
OUT_FILE = 'plot.png'


def get_attack_ids(file):
    lines = file.readlines()
    print(type(lines))
    res = []
    for line in lines:
        js = json.loads(line)
        res.append(js['id'])

    return res


def get_flagged_ids(file):
    lines = file.readlines()
    res = []
    for line in lines:
        js = json.loads(line)
        if js['ids'] is True:
            # if js['ids'] is not False:
            res.append(js['id'])
    print(len(res))
    return res


if __name__ == "__main__":
    in_file = open(IN_FILE, 'r+')
    print(in_file)
    attack_file = open(ATTACKFILE, 'r+')

    flagged_ids = get_flagged_ids(in_file)
    attack_ids = get_attack_ids(attack_file)

    fig, ax = plt.subplots(1)
    plt.xlabel("Packet ID")
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.75])
    ax.set_yticklabels(["Alerts", "Attacks"])

    ax.vlines(flagged_ids, 0, 0.5, colors='b')
    ax.vlines(attack_ids, 0.5, 1, color='r')
    plt.savefig(OUT_FILE)
