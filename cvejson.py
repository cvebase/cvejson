from os import scandir, path
from git import Repo
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
    y = yaml.load(b.split("---")[1], Loader=yaml.Loader)
    cve_id = y["id"]
    pocs = [x for x in y["pocs"]]
    pocs.sort()
    return cve_id, pocs


def main():
    # git pull to update if local repo already exists, if not clone new repo
    path_to_repo = "./cvebase.com/"
    if path.isdir(path_to_repo):
        repo = Repo(path_to_repo)
        o = repo.remotes.origin
        o.pull()
    else:
        Repo.clone_from("https://github.com/cvebase/cvebase.com.git", path_to_repo, branch='main', depth=1)

    oj = {}
    for entry in scantree('./cvebase.com/cve/'):
        with open(entry.path, 'r+') as file:
            cve_id, pocs = parse_cve_md(file.read())
            file.close()
            oj[cve_id] = pocs
            # print("{} {}".format(cve_id, pocs))

    with open('cve.json', 'r+') as outfile:
        outfile.truncate(0)
        json.dump(oj, outfile, sort_keys=True, indent=4)


if __name__ == '__main__':
    main()
