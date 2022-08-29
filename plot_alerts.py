#!/usr/bin/env python3
import argparse
import datetime
import gzip
import json
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt

IDSs = [ ]
ATTACKFILE = None
DATASETNAME = ""
GAPTIME = 30 # Gap has to be at least x minutes to be skipped


# Wrapper for hiding .gz files
def open_file(filename, mode):
    if filename.endswith(".gz"):
        return gzip.open(filename, mode=mode, compresslevel=settings.compresslevel)
    else:
        return open(filename, mode=mode, buffering=1)

def plot(ax):
    global IDSs, ATTACKFILE, DATASETNAME, GAPTIME

    # PLOT IDS ALARMS
    I = 1
    for IDS, label in IDSs:
        I -= 1
        gaps = []
        length = 0
        ALERT = []

        # print("Processing: {} ({}/{})".format(label, -I + 1, len(IDSs)))
        try:
            with open_file(IDS, "r") as f:
                last_timestamp = None
                lines = f.readlines()
                length = len(lines)

                for line in lines:
                    js = json.loads(line)
                    # print(f"Val: {js['ids']}, check if True: {js['ids'] is not None}")
                    if js['ids'] is not None:
                        # print(f"appending ID for malicious message")
                        ALERT.append(js['id'])
                        # borders = (js['id'], js['id']+1)
                        # rect = matplotlib.patches.Rectangle((borders[0], 0), borders[1] - borders[0], 0.5,
                        #                                     color=u'#000000',
                        #                                     linewidth=0)
                        # ax.add_patch(rect)
                ALERT = sorted(ALERT)

                # while line:
                #     js = json.loads(line)
                #     t = datetime.datetime.fromtimestamp(js["timestamp"])
                #
                #     if last_timestamp is None:
                #         last_timestamp = t
                #         START = js["timestamp"]
                #     elif t - last_timestamp > datetime.timedelta(minutes=GAPTIME):
                #         delta = t - last_timestamp
                #         gaps.append( (js["timestamp"] - START, delta) )
                #     last_timestamp = t
                #
                #     relativ_time = js["timestamp"] - START
                #     for gap in gaps:
                #         relativ_time -= gap[1].total_seconds()
                #
                #     T.append( relativ_time )
                #     # ALERT.append(js["ids"])
                #
                #     line = f.readline()
                #     if js['malicious']:
                #         ALERT.append(js['id'])
        except EOFError:
            print("WARNING: File not closed properly! Some data is still missing!\n")

        # rect = matplotlib.patches.Rectangle((borders[0], 0), borders[1] - borders[0], 1, color=u'#a50303', linewidth=0)
        # ax.add_patch(rect)
        # ALERT = ALERT.sort()
        # print(ALERT)
        # for a in ALERT:
        #     # print(a)
        print(ALERT)
        print(len(ALERT))
        # for a in ALERT:
        #     plt.axvline(x=a, ymin=0, ymax=0.5, color=u'#000000')?
        ax.fill_between(ALERT, 0, 0.5, facecolor=u'#000000', linewidth=1)

    # END = js["timestamp"]

    # PLOT ATTACKS
    print("Processing attacks")
    ATTACKS = []
    with open(ATTACKFILE) as f:

        for attack in json.load(f):
            # print(f"Current attack: {attack}")
            id = attack['id']

            # for gap in gaps:
            #     if attack["start"] - START > gap[0]:
            #         start -= gap[1].total_seconds()
            #         end -= gap[1].total_seconds()

            borders = (id, id+1)
            ATTACKS.append(borders)

            rect = matplotlib.patches.Rectangle((borders[0], 0.5), borders[1] - borders[0], 0.5, color=u'#a50303', linewidth=0)
            ax.add_patch(rect)

    # PLOT SETTINGS

    # end = END - START
    # for gap in gaps:
    #     end -= gap[1].total_seconds()

    # Nticks = 10
    # ticksEvery = end // 3600 / Nticks
    # ax.set_xticks(len(ATTACKS))
    # ax.set_xticklabels([ "%.1f" % (ticksEvery * i) for i in range(Nticks * 2) ])
    # ax.set_xlim(0, end)

    ax.set_ylabel(DATASETNAME, fontweight=1000, fontsize='x-large', labelpad=5 )
    ax.yaxis.set_label_position("right")

    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.75])
    ax.set_yticklabels([DATASETNAME] + ["Attacks"])
    ax.tick_params(axis='y', which='both', color='white')


def main():
    global IDSs, ATTACKFILE, DATASETNAME, GAPTIME

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--attacks",
        metavar="attacks",
        help="Path to attacks.json file of the dataset.",
        required=True,
    )

    parser.add_argument(
        "--dataset",
        metavar="dataset",
        help="Name of the dataset to put on the plot (Default: '')",
        required=False,
    )

    parser.add_argument(
        "--title",
        metavar="title",
        help="Title to put on the plot (Default: '')",
        required=False,
    )

    parser.add_argument(
        "--output",
        metavar="output",
        help="File to save the plot to. (Default: '': Show in matplotlib window)",
        required=False,
    )

    parser.add_argument(
        'IDSs',
        metavar='IDS',
        nargs='+',
        help='IDS classification files'
    )

    args = parser.parse_args()

    IDSs = [ (IDS, Path(IDS).stem.replace(".json", "").replace(".ipal", "").replace(".state", "")) for IDS in args.IDSs ]
    ATTACKFILE = args.attacks
    if args.dataset:
        DATASETNAME = args.dataset

    # Plot
    fig, ax = plt.subplots(1)

    plt.xlabel("Packet ID")
    plot(ax)

    if args.title:
        plt.title(args.title)

    print("Plotting...")
    if args.output is not None:
        plt.savefig(args.output)
    else:
        plt.show()

if __name__ == "__main__":
    main()
