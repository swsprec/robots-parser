import argparse
import os.path

import RobotsDataClasses
import rfcRegexes
import logging
import coloredlogs
import datetime
import reMe
from urllib.parse import urlparse
import Levenshtein
import json
import sys

logger = logging.getLogger(__name__)
coloredlogs.install(level='debug')


def parse_cmd():
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', "--file",
                        required=True,
                        help="robots files input, or directory of robots files",
                        dest="robotsIn")
    parser.add_argument('-w', "--wayback",
                        required=False,
                        help="Flag indicating robots are coming from wayback with metadata in the first line of the file",
                        dest="wayback",
                        action=argparse.BooleanOptionalAction,
                        default=False)

    parser.add_argument('-s', "--spec",
                        required=False,
                        default=None,
                        help="file with special parsing rules for specific files",
                        dest="specialRules")

    parser.add_argument("-o", "--output",
                        required=False,
                        help="file to append to with json, default is printing to stdout",
                        dest="outStream",
                        default=sys.stdout)
    parser.add_argument("-i", "--inplace",
                        required=False,
                        help="inplace file output mode, if activated, will output a file in place with .json extension",
                        dest="inPlace",
                        action=argparse.BooleanOptionalAction,
                        default=False)
    # Arguments for metadata files (grouping of files robots or not)
    parser.add_argument("--robots-class",
                        required=False,
                        default="/tmp/robotsClass.txt",
                        help="output file to store files that are most likely robots files",
                        dest="rclass")
    parser.add_argument("--empty-class",
                        required=False,
                        default="/tmp/emptyClass.txt",
                        help="output file to store files that are most likely empty",
                        dest="eclass")
    parser.add_argument("--non-empty-non-robots-class",
                        required=False,
                        default="/tmp/nonRobotsClass.txt",
                        help="output file to store files that are most likely not robots files",
                        dest="nenrclass")
    parser.add_argument("--non-empty-non-robots-threshold-class",
                        required=False,
                        default="/tmp/nonRobotsThresholdClass.txt",
                        help="output file to store files that are most likely not robots files via threshold",
                        dest="tclass")
    parser.add_argument("--unknown",
                        required=False,
                        default="/tmp/unknownClass.txt",
                        help="output file to store files that are not classifiable for further inquiry",
                        dest="uclass")

    return parser.parse_args()


def get_meta_data(wayback: str):
    regedLine = reMe.search(RobotsDataClasses.regexStore['robotFileSeperator'], wayback)
    FullUrl = regedLine.group(1)
    timestamp = datetime.datetime.strptime(regedLine.group(3), "%Y%m%d%H%M%S")
    url = urlparse(regedLine.group(4)).netloc
    return FullUrl, url, timestamp


def distance_guess(s):
    # Now things get complicated, need to check if it is close enough to
    #   any known directive to confidently declare it as such
    #       Attempt #1: edit distance
    compList = []
    for key in rfcRegexes.KNOWN_LINES:
        if key == "comment":
            continue
        elif key == "acap-":
            s = s[:len(key)]
        elif key == "-sitemap":
            s = s[-len(key):]
        tmp = Levenshtein.ratio(s, key, score_cutoff=0.65)
        matchingBs = Levenshtein.matching_blocks(Levenshtein.editops(s, key), s, key)
        matchingBsorted = sorted(matchingBs, key=lambda thing: thing.size, reverse=True)[0]
        if tmp:
            compList.append((key, tmp, matchingBsorted))
    compList = sorted(compList, key=lambda dist: dist[1], reverse=True)
    # If nothing surpasses our threshold (score_cutoff), return unguessable
    if not compList:
        return None
    elif len(compList) == 1:
        return compList[0][0]
    else:

        # Something like a waterfall, tier'd confidence decisions
        if compList[0][1] > compList[1][1] * 1.15:
            # High confidence the first option is the best option
            return (compList[0][0])

        elif compList[0][1] > compList[1][1]:
            # Is there a determining difference in the matching block size?
            if compList[0][2].size > compList[1][2].size:
                # Decent confidence that the first option is the closest still
                return (compList[0][0])
            elif compList[0][2].size < compList[1][2].size:
                # could be a better match for the second one 
                return (compList[1][0])
            else:
                # Block sizes are equal
                return None


        elif compList[0][1] == compList[1][1]:
            # Is there a determining difference in the matching block size?
            if compList[0][2].size > compList[1][2].size:
                # Decent confidence that the first option is the closest still
                return (compList[0][0])
            elif compList[0][2].size < compList[1][2].size:
                # Decent confidence that the second option is the closest still
                return (compList[1][0])

        return None


def directive_guess(lineIn):
    dir_guess = None
    val = None
    # Check if there's a ":" separator
    tmp = lineIn.strip().split(":", maxsplit=1)
    if not tmp or len(tmp) == 1:
        # no separator char, can't really do anything with this
        # hail mary split on spaces
        tmp2 = lineIn.strip().split(maxsplit=1)
        if not tmp2 or len(tmp2) == 1:
            # no spaces to separate either
            # check for "="
            tmp3 = lineIn.strip().split("=",maxsplit=1)
            if not tmp3 or len(tmp3) == 1:
                return None, None, None
            else:
                dir_guess = distance_guess(tmp3[0])
                val = tmp3[1]
                return dir_guess, val, tmp3[0]
            return None, None, None
        else:
            # there's a space separator at least
            dir_guess = distance_guess(tmp2[0])
            val = tmp2[1]
            return dir_guess, val, tmp2[0]

    elif len(tmp) == 1:
        return None, None, None

    else:
        # There's at least a ":" seperator
        dir_guess = distance_guess(tmp[0])
        val = tmp[1]
        return dir_guess, val, tmp[0]


'''
Input: lineIn (invariant, not empty, and last char is \n
'''
def identify_line(lineIn):
    # Check if line isn't empty
    matchedDir = None
    compliant = False
    val = None
    rawDir = None
    for knownLine, stuffToUnpack in rfcRegexes.KNOWN_LINES.items():
        reg, ngroups, expectedVal = stuffToUnpack
        tmp = reMe.fullmatch(reg, lineIn)
        if tmp:
            matchedDir = knownLine
            compliant = True
            val = (ngroups, tmp)
            break

    if not matchedDir:
        # Not RFC Compliant
        assert(compliant == False)
        matchedDir, val, rawDir = directive_guess(lineIn)



    return matchedDir, compliant, val, rawDir


def parse_robot_file(filename, start=None, end=None, wayback_arg=None):

    line_number = 0
        
    with open(filename, "r") as rIn:
        if wayback_arg:
            wayback = rIn.readline().strip()
            line_number += 1
            waybackUrl, domain, date = get_meta_data(wayback)
        else:
            waybackUrl = f"{filename}"
            domain = "localhost"
            date = datetime.datetime.now()
        robotsObj = RobotsDataClasses.RobotsFile(waybackUrl, date, domain, filename)
        curUA = None
        for line in rIn:
            line_number += 1

            if start and end:
                if line_number <= start:
                    continue
                if line_number >= end - 1:
                    break

            # Skip blank lines
            if line.strip():
                if line[-1] != "\n":
                    line += "\n"

                directive, compliant, val, rawDir = identify_line(line)

                raw_line = line

                if directive and compliant:
                    # Was an exact match, grab correct val now
                    # Check if user-agent, to set the new active UA
                    ngroups, regMatch = val
                    if directive == "user-agent":
                        curUA = regMatch["token"]

                    if directive == "comment":
                        raw_directive = "comment"
                    else:
                        raw_directive = regMatch["directive"]

                    d = RobotsDataClasses.Directive(curUA, directive,
                                                    raw_directive,
                                                    {y: regMatch[y] for y in ngroups},
                                                    regMatch.group(0),
                                                    compliant)
                elif directive:
                    # This is a guess, gotta be careful about vals and formatting
                    assert(val is None or type(val) == str)
                    if val:
                        assert(val[0] != "#")


                    dir_val_parsed = {"matched": None, "eolComment": None}

                    comments_check = val.split("#", maxsplit=1)
                    if len(comments_check) > 1:
                        # There is a comment somewhere
                        dir_val_parsed["eolComment"] = comments_check[1]
                        val = comments_check[0]

                    val = val.strip()

                    matchboi = reMe.match(rfcRegexes.KNOWN_LINES[directive][2], val)
                    if matchboi is not None:
                        dir_val_parsed["matched"] = matchboi[0]
                    else:
                        dir_val_parsed["matched"] = matchboi

                    # Hunt for UA
                    if directive == "user-agent":
                        curUA = dir_val_parsed["matched"]

                    d = RobotsDataClasses.Directive(curUA,
                                                    directive,
                                                    rawDir,
                                                    dir_val_parsed,
                                                    raw_line.strip(),
                                                    compliant)



                else:
                    dir_val_parsed = {"rawNoComment": None, "eolComment": None}
                    if val:
                        comments_check = val.split("#", maxsplit=1)
                    else:
                        comments_check = []

                    if len(comments_check) > 1:
                        # There is a comment somewhere
                        dir_val_parsed["eolComment"] = comments_check[1]
                        dir_val_parsed["rawNoComment"] = comments_check[0]
                    else:
                        dir_val_parsed["rawNoComment"] = raw_line.strip()


                    d = RobotsDataClasses.Directive(curUA,
                                                    directive,
                                                    "",
                                                    dir_val_parsed,
                                                    raw_line.strip(),
                                                    compliant
                                                    )

                robotsObj.add_directive(d)

    return robotsObj

def guess_if_robots(robots_obj: RobotsDataClasses.RobotsFile):

    number_directives = len(robots_obj.directives)
    number_compliant = 0
    number_unknown = 0
    for dirID, dir in robots_obj.directives.items():
        if dir.compliance:
            number_compliant += 1
        if dir.directive == 'unknown':
            number_unknown += 1


    if number_directives > 0:
        if number_compliant > 0:
            return "ROBOTS"
        else:
            if number_directives - number_unknown > 0:
                if number_unknown / number_directives > .9:
                    return "NON-EMPTY, NON-ROBOTS, THRESHOLD"
                else:
                    return "???"
            else:
                return "NON-EMPTY, NON-ROBOTS"
    else:
        return "EMPTY"



def main():
    args = parse_cmd()

    specialRulesDict = dict()
    if args.specialRules:
        with open(args.specialRules, "r") as specialRulesIn:
            for line in specialRulesIn:
                line = line.strip()
                file, start, stop = line.split(":")
                if file not in specialRulesDict:
                    specialRulesDict[file] = [int(start), int(stop)]

    group_names = ["EMPTY", "ROBOTS", "NON-EMPTY, NON-ROBOTS",
                   "NON-EMPTY, NON-ROBOTS, THRESHOLD", "???"]
    group_meta_files = [args.eclass, args.rclass, args.nenrclass,
                        args.tclass, args.uclass]

    if os.path.isdir(args.robotsIn):
        # proceed as directory
        directory = args.robotsIn
        tmp = os.listdir(directory)
        abs_dir = os.path.abspath(directory)
        files_to_iterate = [os.path.join(abs_dir, file) for file in tmp if not file.endswith(".json")]

    elif os.path.isfile(args.robotsIn):
        files_to_iterate = [os.path.abspath(args.robotsIn)]

    else:
        print(f"What are you doing? Not passing a directory or file to the parser...")
        sys.exit(1)

    for full_filename in files_to_iterate:
        try:
            if full_filename in specialRulesDict:
                robots = parse_robot_file(full_filename,
                                          start=specialRulesDict[full_filename][0],
                                          end=specialRulesDict[full_filename][1],
                                          wayback_arg=args.wayback)
            else:
                robots = parse_robot_file(full_filename, wayback_arg=args.wayback)
        # Happens when a .swp file exists
        except UnicodeDecodeError:
            print(f"swp file exists: {full_filename}")
            sys.exit(1)

        with open(group_meta_files[group_names.index(guess_if_robots(robots))], "a+") as metaOut:
            print(full_filename, file=metaOut)

        if args.inPlace:
            #output in place 
            with open(f"{full_filename}.json", "w") as jsonOut:
                print(robots.to_json(), file=jsonOut)
        else:
            if isinstance(args.outStream, str):
                with open(args.outStream, "a+") as fout:
                    print(robots.to_json(), file=fout)
            else:
                print(robots.to_json())


    return 0




if __name__ == "__main__":
    main()
