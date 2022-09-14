import copy
import os
import yaml


def get_requirements(file_path, parse_includes=True):
    with open(file_path, "r") as f:
        data = yaml.load(f)

    requirements = []

    def walk(d):
        glob_products = []

        for k, v in d.items():
            if k == "products":
                glob_products = v

        for k, v in d.items():
            if k == "requirement_list":
                for req in v:
                    if "products" not in req:
                        req["products"] = copy.deepcopy(glob_products)
                    if len(req["products"]) == 0:
                        print "WARNING! Requirement {} has no products specified".format(req["id"])
                    if "marks" in req:
                        if "ready" in req["marks"] and req["marks"]["ready"] is False:
                            print "WARNING! Requirement {} is not ready".format(req["id"])
                    requirements.append(req)
            if k == "includes" and parse_includes:
                for inc_file_path in v:
                    inc_file_full_path = os.path.join(os.path.dirname(file_path), inc_file_path)
                    requirements.extend(get_requirements(inc_file_full_path))
            elif isinstance(v, dict):
                walk(v)

    walk(data)
    return requirements


def get_plain_txt(requirements):
    txt = ""
    requirements = sorted(requirements, key=lambda r: r["id"])
    for req in requirements:
        txt += req["id"] + "\n"
        txt += "    description: {}\n".format(req["description"])
        if "note" in req:
            txt += "    note: {}\n".format(req["note"])
    return txt


def get_plain_csv(requirements):
    txt = "id\tdescription\tnote\n"
    requirements = sorted(requirements, key=lambda r: r["id"])
    for req in requirements:
        txt += "{}\t{}".format(req["id"], req["description"])
        if "note" in req:
            txt += "\t{}\n".format(req["note"])
        else:
            txt += "\n"
    return txt


requirements = get_requirements("driver/flashless_linux.yaml")
print get_plain_csv(requirements)
