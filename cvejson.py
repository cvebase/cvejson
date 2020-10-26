import argparse
from os import scandir, path
from ruamel import yaml
import json


def scantree(p):
    # Recursively yield DirEntry objects for given directory
    for entry in scandir(p):
        if entry.is_dir(follow_symlinks=False):
            yield from scantree(entry.path)
        else:
            yield entry


def parse_cve_md(b):
    y = yaml.load(b.split('\n---')[0], Loader=yaml.Loader)
    cve_id = y["id"]
    pocs = [x for x in y["pocs"]]
    pocs.sort()
    return cve_id, pocs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cvebase-path', required=True, help='path to cvebase.com repo')
    args = parser.parse_args()

    if path.exists(args.cvebase_path):
        path_to_cves = path.join(args.cvebase_path, 'cve')
    else:
        print('error in path to cvebase.com repo')
        exit(1)

    oj = {}
    for entry in scantree(path_to_cves):
        with open(entry.path, 'r+') as file:
            cve_id, pocs = parse_cve_md(file.read())
            file.close()
            oj[cve_id] = pocs
            # print("{} {}".format(cve_id, pocs))

    with open('cve.json', 'w+') as outfile:
        outfile.truncate(0)
        json.dump(oj, outfile, sort_keys=True, indent=4)
        outfile.close()


if __name__ == '__main__':
    main()
