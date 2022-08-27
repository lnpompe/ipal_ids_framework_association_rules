import json
import sys

# expects eval_file to point to a file which is the output from the live phase on non-malicious data
def eval_fpr(eval_file):
    print(f"Computing False Positive Rate for file {eval_file}")

    # false positives
    fp = 0
    # true negatives
    tn = 0

    with open(eval_file, "r") as input_file:
        for line in input_file.readlines():
            packet = json.loads(line)
            if packet["ids"] is not None:
                if packet["ids"]:
                    fp = fp + 1
                elif not packet["ids"]:
                    tn = tn + 1
    print(f"False Positives: {fp}")
    print(f"True Negatives: {tn}")
    print(f"False Positive Rate: {fp/(fp+tn)}")


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print("Which property would you like to evaluate?")
        print("1. False Positive Rate")
        eval_property = int(input())

        print("Which file would you like to evaluate?")
        eval_file = input()

    else:
        eval_property = int(sys.argv[1])
        eval_file = sys.argv[2]

    if eval_property == 1:
        eval_fpr(eval_file)
