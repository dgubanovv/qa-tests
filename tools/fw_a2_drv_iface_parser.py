# Steps to use this generator:
#     # Install necessary packages
#     sudo apt-get -y install libclang-5.0-dev
#     sudo apt-get -y install python-clang-3.9
#     sudo pip install ctypeslib2
#
#     # Download MIPS toolchain
#     wget https://codescape.mips.com/components/toolchain/2017.10-08/Codescape.GNU.Tools.Package.2017.10-08.for.MIPS.MTI.Bare.Metal.CentOS-5.x86_64.tar.gz
#     tar -C /home/aqtest -xzf Codescape.GNU.Tools.Package.2017.10-08.for.MIPS.MTI.Bare.Metal.CentOS-5.x86_64.tar.gz
#
#     # Clone FW repository and generate fw_a2_drv_iface.py
#     cd /home/aqtest && git clone git@gitlab.rdc-lab.marvell.com:fw/atlantic2.git ; cd -
#     python fw_a2_drv_iface_parser.py -t /home/aqtest/mips-mti-elf/ -r /home/aqtest/atlantic2/ /home/aqtest/atlantic2/firmware/src/main/drv.hpp -o fw_a2_drv_iface_structures.py

import logging
import os
import re

from argparse import ArgumentParser
from StringIO import StringIO

from ctypeslib.codegen import clangparser
from ctypeslib.codegen import codegenerator

if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument("-t", "--toolchain",
                        help="path to mips-mti-elf directory (which contains 2017.10-08 dir)")

    parser.add_argument("-r", "--repository",
                        help="path to atlantic2 directory (repository root)")

    parser.add_argument("-o", "--output",
                        help="output file path")

    parser.add_argument("--debug", action="store_true",
                        help="turn on parser's debug prints")

    parser.add_argument("header",
                        help="path to driver interface header file")

    args = parser.parse_args()

    clang_flags = ["-std=c++14", "-target", "i386-Linux"]

    if args.debug:
        log = logging.getLogger('clangparser')
        log.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        log.addHandler(handler)

    if args.toolchain:
        clang_flags.extend([
            "-I{}".format(os.path.join(args.toolchain, "2017.10-08/mips-mti-elf/include/")),
            "-I{}".format(os.path.join(args.toolchain, "2017.10-08/mips-mti-elf/include/c++/6.3.0/")),
            "-I{}".format(os.path.join(args.toolchain,
                                       "2017.10-08/mips-mti-elf/include/c++/6.3.0/mips-mti-elf/micromips-r2-hard-nan2008-newlib/lib/"))
        ])

    if args.repository:
        clang_flags.extend([
            "-I{}".format(os.path.join(args.repository, "firmware/src")),
            "-I{}".format(os.path.join(args.repository, "firmware/src/include"))
        ])

    with open(args.header) as f:
        sources = f.readlines()

    # Modify sources for parser
    # 1. Remove namespace
    for i in range(len(sources)):
        if re.search(r"namespace\s+\w+", sources[i]):
            sources[i] = "// {}".format(sources[i])

            for j in range(len(sources) - 1, -1, -1):
                if "}" in sources[j]:
                    sources[j] = "// {}".format(sources[j])
                    break

            break
    # 2. Remove static asserts
    asserts = []
    for i in range(len(sources)):
        if "static_assert" in sources[i]:
            m = re.search(r"static_assert\s*\(\s*sizeof\s*\(\s*(\w+)\s*\)\s*==\s*([0-9A-Fa-fx]+)\s*,\s*(\".*\")",
                          sources[i])
            if m:
                asserts.append("assert ctypes.sizeof({}) == {}, {}".format(m.group(1), m.group(2), m.group(3)))

            m = re.search(
                r"static_assert\s*\(\s*offsetof\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*==\s*([0-9A-Fa-fx]+)\s*,\s*(\".*\")",
                sources[i])
            if m:
                asserts.append("assert {}.{}.offset == {}, {}".format(m.group(1), m.group(2), m.group(3), m.group(4)))
            m = re.search(
                r"static_assert\s*\(\s*\(\s*offsetof\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*%\s*([0-9A-Fa-fx]+)\s*\)\s*==\s*([0-9A-Fa-fx]+),\s*(\".*\")",
                sources[i])
            if m:
                asserts.append(
                    "assert {}.{}.offset % {} == {}, {}".format(m.group(1), m.group(2), m.group(3), m.group(4),
                                                                m.group(5)))

            sources[i] = "// {}".format(sources[i])

    # 3. Remove forward class declarations
    for i in range(len(sources)):
        if re.search(r"class\s+\w+\s*\;", sources[i]):
            sources[i] = "// {}".format(sources[i])

    gen_output = StringIO()

    clang_parser = clangparser.Clang_Parser(flags=clang_flags)
    clang_parser.parse_string("".join(sources))
    code_generator = codegenerator.Generator(gen_output)
    code_generator.generate(clang_parser, clang_parser.get_result())

    result = gen_output.getvalue().splitlines()

    # Modify sources for python import
    # 1. Remove struct__reent mentions (from mips toolchain headers)
    for i in range(len(result)):
        if "struct__reent" in result[i]:
            result[i] = "# {}".format(result[i])
        if "'_global_impure_ptr'," in result[i]:
            result[i] = result[i].replace("'_global_impure_ptr',", "")
        if "'_impure_ptr'," in result[i]:
            result[i] = result[i].replace("'_impure_ptr',", "")
    # 2. Remove 0 length bitfields
    for i in range(len(result)):
        if re.search(r"ctypes\.\w+, 0", result[i]):
            result[i] = "# {}".format(result[i])
    # 3. Add asserts
    result.extend(asserts)
    # TODO: remove this
    # 4. For some reason sometimes library incorrectly processes fields uint32_t :32
    for i in range(len(result)):
        result[i] = result[i].replace("c_uint64, ", "c_uint32, ")
    # TODO: remove this
    # 5. struct statistics_t is generated incorrectly due to 64-bit alignment
    for i in range(len(result)):
        if "struct_c__SA_statistics_t._fields_" in result[i]:
            result[i + 2] = "{}\n    ('_1', ctypes.c_uint32),".format(result[i + 2])
            result[i + 3] = "{}\n    ('_2', ctypes.c_uint32),".format(result[i + 3])

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(result))
    else:
        print("\n".join(result))
