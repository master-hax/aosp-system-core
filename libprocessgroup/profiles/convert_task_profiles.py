#!/usr/bin/env python
import json
import sys
import collections

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: {} task_profiles.json".format(sys.argv[0]))
        return 1
    file_name = sys.argv[1];
    with open(file_name, 'r') as file:
        js = json.JSONDecoder(object_pairs_hook=collections.OrderedDict).decode(file.read())

    for profile in js.get("Profiles"):
        for action in profile.get("Actions") or []:
            params = action.get("Params")
            if params:
                assert isinstance(params, dict), "Already converted."
                new_params = []
                for key, value in params.items():
                    new_params.append({"Name": key, "Value": value})
                action["Params"] = new_params

    print(json.dumps(js, indent=2))
if __name__ == '__main__':
    exit(main())
