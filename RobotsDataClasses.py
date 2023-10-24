from datetime import datetime
from dataclasses import dataclass, field, is_dataclass, asdict
from typing import Literal, Any, Optional, Union
from types import SimpleNamespace
from itertools import count
import reMe
import re
import rfcRegexes
import json

MAX_PATH_DEPTH = 100

def load_json_string(s: str):
    return json.loads(s, object_hook=lambda d: SimpleNamespace(**d))


regexStore = {
    "robotFileSeperator": re.compile(r"(^(https:\/\/web\.archive\.org\/web\/)([0-9]{14})(?:if\_)?\/(.*)$)"),
}


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if is_dataclass(o):
            return asdict(o)
        elif isinstance(o, set):
            return list(o)
        elif isinstance(o, RobotsFile):
            return o.__dict__
        elif isinstance(o, re.Match):
            return o[0]
        elif isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)
    

KNOWN_DIRECTIVES = \
    Literal[
        'user-agent',
        'crawl-delay',
        'request-rate',
        'allow',
        'disallow',
        'block',
        'noindex',
        'nosnippet',
        'sitemap',
        '-sitemap',
        'host',
        'ignore',
        'clean-param',
        'host-load',
        'visit-time',
        'noarchive',
        'nofollow',
        'acap-',
        'comment'
    ]


@dataclass
class Directive:
    user_agent: str
    directive: KNOWN_DIRECTIVES
    raw_directive: str
    value: Any
    raw_value: str
    compliance: bool
    id: int = field(default_factory=count().__next__)

    @staticmethod
    def from_json(id, json_dct):
        ID = id
        ua = json_dct['user_agent']
        dirName = json_dct['directive']
        rDir = json_dct['raw_directive']
        v = json_dct['value']
        rv = json_dct['raw_value']
        compli = json_dct['compliance']
        return Directive(ua, dirName, rDir, v, rv, compli, ID)

@dataclass
class PathNode:
    key: str = field(compare=True)
    ids: list = field(default_factory=list)
    children: dict = field(default_factory=dict)

    def add_id(self, id: int):
        self.ids.append(id)

    @staticmethod
    def from_json(json_dct):
        # Terminal Condition
        if json_dct is None:
            return None
        elif not json_dct['children']:
            #hit a terminal node
            return PathNode(json_dct['key'], json_dct['ids'], dict())
        else:
            paths = list()
            for kidKey, kidPathNode in json_dct['children'].items():
                paths.append(PathNode.from_json(kidPathNode))

            children_current = {k.key: k for k in paths}
            return PathNode(json_dct['key'], json_dct['ids'], children_current)


class RobotsFile:
    wayback_url: str
    date: datetime
    domain: str
    filePath: str
    user_agents: set[(int,str)]
    directives: dict[int:Directive]
    comments: list[(int, str)]
    urlsFromComments: set[(int,str)]
    pathsFromComments: set[(int,str)]
    # Dict:dict with nodes having ID's linking back to the parent directive
    # {"/": {"ids": [], "children": {"path": {"ids": [], "children": {...}}}}}
    revealedPathTree: Union[PathNode, None] = None

    def to_json(self, indent=None):
        return json.dumps(self, indent=indent, cls=EnhancedJSONEncoder)

    @staticmethod
    def from_json(json_dct):
        wayback_url = json_dct['wayback_url']
        date = datetime.fromisoformat(json_dct['date'])
        domain = json_dct['domain']
        filePath = json_dct['filePath']
        user_agents = set()
        for pair in json_dct['user_agents']:
            user_agents.add(tuple(pair))

        directives = dict()
        for dirID, dirDict in json_dct['directives'].items():
            dirID = int(dirID)
            directives[dirID] = Directive.from_json(dirID, dirDict)

        comments = list()
        for tup in json_dct['comments']:
            comments.append(tuple(tup))

        urlsFromComments = set()
        for pair in json_dct['urlsFromComments']:
            urlsFromComments.add(tuple(pair))

        pathsFromComments = set()
        for pair in json_dct['pathsFromComments']:
            pathsFromComments.add(tuple(pair))

        revealedPathTree = PathNode.from_json(json_dct['revealedPathTree'])

        return RobotsFile(wayback_url, date, domain,
                          filePath, user_agents, directives,
                          comments, urlsFromComments,
                          pathsFromComments, revealedPathTree)



    def __init__(self, wayback_url, date, domain, filePath, user_agents=None, directives=None,
                 comments=None, urlsFromComments=None, pathsFromComments=None, revealedPathTree=None):
        if user_agents is None:
            self.user_agents = set()
        else:
            self.user_agents = user_agents
        if directives is None:
            self.directives = dict()
        else:
            self.directives = directives
        if comments is None:
            self.comments = list()
        else:
            self.comments = comments

        self.wayback_url = wayback_url
        self.date = date
        self.domain = domain
        self.filePath = filePath

        if urlsFromComments is None:
            self.urlsFromComments = set()
        else:
            self.urlsFromComments = urlsFromComments
        if pathsFromComments is None:
            self.pathsFromComments = set()
        else:
            self.pathsFromComments = pathsFromComments

        self.revealedPathTree = revealedPathTree

    def _add_path_recurse(self, key: list, idx: int, robotNode: PathNode, dirID: Any):
        if idx >= len(key):
            return

        if key[idx] not in robotNode.children:
            robotNode.children[key[idx]] = PathNode(key[idx], [dirID])
        else:
            robotNode.children[key[idx]].add_id(dirID)

        tmp = idx + 1
        self._add_path_recurse(key, tmp, robotNode.children[key[idx]], dirID)

    '''
    INPUT: DirectiveID, PathString
            Unique to dir, is parsable path
    '''

    def add_path(self, directive_id, path_str):
        # check if valid path
        if path_str:
            tmp = reMe.fullmatch(rfcRegexes.path_pattern, path_str)
            if tmp:
                # check if there is already a revealedTree
                assert (path_str[0] == "/")
                if not self.revealedPathTree:
                    self.revealedPathTree = PathNode("", [-1])
                # Add directive ID to root node
                self.revealedPathTree.add_id(directive_id)
                path_list = path_str.split("/")
                path_list = path_list[:1] + [i for i in path_list[1:] if i != ""]
                # Cut max depth to max depth, avoids python recursion errors
                path_list = path_list[:MAX_PATH_DEPTH]
                # add to revealedPathTree if it's more than just "/"
                if len(path_list) > 1:
                    try:
                        self._add_path_recurse(path_list, 1, self.revealedPathTree, directive_id)
                    except RecursionError:
                        #This will never happen, since we apply the cutoff before calling
                        pass

            else:
                # Not a valid path string, skipping...
                pass
        else:
            # no string passed, empty field probably
            pass

    def extract_paths(self, s: str):
        return reMe.findall(rfcRegexes.complied_path_pattern, s)

    def extract_uris(self, s: str):
        noschemes, cleaned_s = reMe.findall(rfcRegexes.compiled_no_scheme_uri, s), reMe.sub(rfcRegexes.compiled_no_scheme_uri, " ", s)
        withschemes, cleaned_s = reMe.findall(rfcRegexes.compiled_absuri, cleaned_s), reMe.sub(rfcRegexes.compiled_absuri, " ", cleaned_s)

        return noschemes + withschemes, cleaned_s

    def add_comment(self, comment_string: str, directive_id: int):

        uris, cleaned_comment_string = self.extract_uris(comment_string)
        for uri in uris:
            self.urlsFromComments.add((directive_id, uri.strip()))

        paths = self.extract_paths(cleaned_comment_string)
        for path in paths:
            self.pathsFromComments.add((directive_id, path))
            self.add_path(directive_id, path)
        self.comments.append((directive_id, comment_string))

    def add_directive(self, d: Union[Directive, None]):
        # State 1: Full regex match i.e. compliant
        #   can pull values out using named groups and add accordingly
        if d.compliance:
            if d.directive == "user-agent":
                self.user_agents.add((d.id, d.value["token"]))

            elif d.directive == "comment":
                self.add_comment(d.value["comment"], d.id)

            # Check every directive for an eolComment except comment
            if d.value["eolComment"] not in ["\n", ""] and d.directive != "comment":
                self.add_comment(d.value["eolComment"], d.id)

            if "path" in d.value.keys():
                self.add_path(d.id, d.value["path"])

            elif d.directive == "acap-":
                matched_paths = self.extract_paths(d.value["val"])
                for x in matched_paths:
                    self.add_path(d.id, x)


            if d.id not in self.directives:
                self.directives[d.id] = d
            else:
                raise ValueError(f"duplicate ID's attempted to add into the robotsObj directives\n"
                                 f"This breaks the invariant that every directive has a unique ID")


        # State 2: Not compliant, but guessable (dir not None)
        #   val will be string, need to check for corresponding values to the directive
        #       should still check for paths / uris to add to master list anyway
        elif d.directive:
            assert(d.directive != "comment")
            if d.directive == "user-agent" and d.value['matched'] is not None:
                self.user_agents.add((d.id, d.value['matched']))

            if d.value["eolComment"] not in ["\n", "", None] and d.directive != "comment":
                self.add_comment(d.value["eolComment"], d.id)

            # Check raw val strings for paths and uris
            if d.directive == "request-rate" and d.value['matched']:
                o = reMe.sub(rfcRegexes.KNOWN_LINES['request-rate'][2], "", d.value['matched'])
            else:
                o = d.raw_value

            matched_paths = self.extract_paths(o)
            for x in matched_paths:
                self.add_path(d.id, x)


            if d.id not in self.directives:
                self.directives[d.id] = d
            else:
                raise ValueError(f"duplicate ID's attempted to add into the robotsObj directives\n"
                                 f"This breaks the invariant that every directive has a unique ID")


        # State 3: Unable to discern (dir and val == None)
        #   Check like comments for paths / urls and save raw string as an unknown directive
        else:
            if d.value["eolComment"] not in ["\n", "", None] and d.directive != "comment":
                self.add_comment(d.value["eolComment"], d.id)

            matched_paths = self.extract_paths(d.value["rawNoComment"])
            for x in matched_paths:
                self.add_path(d.id, x)

            d.directive = 'unknown'

            if d.id not in self.directives:
                self.directives[d.id] = d
            else:
                raise ValueError(f"duplicate ID's attempted to add into the robotsObj directives\n"
                                 f"This breaks the invariant that every directive has a unique ID")


    def __repr__(self):
        return str(self.__dict__)
    def __str__(self):
        return str(self.__dict__)
