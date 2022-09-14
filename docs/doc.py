import importlib
import logging
import os
import re
import sys
import inspect
from collections import OrderedDict

CLASS_NAME_EXCLUDES = ["TestBase"]
TEST_DESCRIPTION_KEYS = ["@description", "@setup"]
SUBTEST_DESCRIPTION_KEYS = ["@description", "@steps", "@result", "@duration"]

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def reformat_doc_string(s):
    return re.compile(" [ ]+").sub("", s)


def get_docstring_key_value(s, k):
    try:
        pos = s.index(k)
    except Exception:
        pass
    else:
        pdesc = ""
        if s[pos + len(k)] == ":":
            pos += 1
        for sym in s[pos + len(k):]:
            if sym == "@":
                break
            pdesc += sym
        return pdesc.rstrip().lstrip()


def parse_test_docstring(class_obj):
    if not hasattr(class_obj, "__doc__"):
        raise Exception("Method {} has no __doc__ attribute".format(class_obj.__name__))

    data = {"name": class_obj.__name__[4:]}
    class_doc = reformat_doc_string(class_obj.__doc__)

    for k in TEST_DESCRIPTION_KEYS:
        v = get_docstring_key_value(class_doc, k)
        if v is not None:
            data[k] = v
    return data


def parse_subtest_docstring(func_obj):
    if not hasattr(func_obj, "__doc__"):
        raise Exception("Method {} has no __doc__ attribute".format(func_obj.__name__))

    data = {"name": func_obj.__name__}
    test_doc = reformat_doc_string(func_obj.__doc__)

    for k in SUBTEST_DESCRIPTION_KEYS:
        v = get_docstring_key_value(test_doc, k)
        if v is not None:
            data[k] = v
    return data


def get_text_test_description(test_description, subtests_description):
    res = ""

    res += "TEST GROUP NAME:\n\n{}\n\n".format(test_description["name"])
    res += "DESCRIPTION:\n\n{}\n\n".format(test_description["@description"])
    res += "SETUP:\n\n"
    for line in test_description["@setup"].split("\n"):
        res += "{}\n".format(line)
    res += "\n"

    res += "SUBTESTS:\n\n"

    for subtest_description in subtests_description:
        res += "    SUBTEST NAME: {}\n\n".format(subtest_description["name"])
        res += "        DESCRIPTION:\n"
        for line in subtest_description["@description"].split("\n"):
            res += "        {}\n".format(line)
        res += "\n"
        res += "        STEPS:\n"
        for line in subtest_description["@steps"].split("\n"):
            res += "        {}\n".format(line)
        res += "\n"
        res += "        EXPECTED RESULT:\n"
        for line in subtest_description["@result"].split("\n"):
            res += "        {}\n".format(line)
        res += "\n"
        res += "        DURATION:\n"
        for line in subtest_description["@duration"].split("\n"):
            res += "        {}\n".format(line)
        res += "\n"

    return res


def parse_test_class(class_obj):
    if not hasattr(class_obj, "__doc__") or class_obj.__doc__ is None:
        raise Exception("Class {} has no __doc__ attribute".format(class_obj))

    test_description = parse_test_docstring(class_obj)
    subtests_description = []

    for k, v in class_obj.__dict__.items():
        if inspect.isfunction(v):
            if k.startswith("test_"):
                test_docs = parse_subtest_docstring(v)
                subtests_description.append(test_docs)

    return test_description, sorted(subtests_description, key=lambda k: k["name"])


def parse_module(mod):
    data = []

    mod_classes = inspect.getmembers(mod, inspect.isclass)
    for name, obj in mod_classes:
        if name.startswith("Test") and name not in CLASS_NAME_EXCLUDES:
            if not hasattr(obj, "__doc__") or obj.__doc__ is None:
                continue
            data.append(parse_test_class(obj))

    return data

file_path = sys.argv[1]

if not file_path.endswith(".py"):
    exit("{} is not a python file".format(file_path))

if not os.path.exists(file_path):
    exit("File {} does not exists".format(file_path))

if not os.path.isfile(file_path):
    exit("{} is not a file".format(file_path))

sys.path.append(os.path.dirname(os.path.abspath(file_path)))
mod = importlib.import_module(os.path.basename(file_path)[:-3])
for test_description, subtests_description in parse_module(mod):
    res = get_text_test_description(test_description, subtests_description)
    print res
