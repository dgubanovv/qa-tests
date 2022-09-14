import os
import re

def write_mem(value, offset):
    return [
        'writereg 0x328 {}'.format(value),
        'writereg 0x32c {}'.format(offset),
        'writereg 0x404 0x2'
    ]

def read_txt(name):
    if not os.path.exists(name):
        raise BaseException('file not found: {}'.format(name))

    re_exec = re.compile('(\ *)exec')

    text = []

    text.append("")
    text.append("#####################################################")
    text.append("### {} >".format(name))
    text.append("#####################################################\n")
    with open(name, 'r') as f:
        for line in f.readlines():
            line = line.replace('\n', '').replace('\r', '')

            m = re_exec.match(line)

            if not m is None:
                file = line[len(m.group(0)) + 1:].strip()
                tabs = '    ' if line[0] == ' ' else ''
                for nl in read_txt(file):
                    text.append(tabs + nl)
            elif line[:1] == '#':
                continue
            else:
                text.append(line)
    text.append("")
    text.append("#####################################################")
    text.append("### < {}".format(name))
    text.append("#####################################################\n")
    return text

def parse(text):
    val = ''
    offset = 0

    re_addr = re.compile('(\ *)addr = \$BASEADDR.*')
    re_writemem = re.compile('(\ *)mac.mcp.writemem ([$a-zA-z0-9]+) ([$a-zA-z0-9]+) .*')
    re_offset = re.compile('(\ *)addr = \$addr \+ (\d+).*')

    prev = None

    new_text = []
    for i, line in enumerate(text):
        line = line.replace('-l nul', '-l cli')
        m_adr = re_addr.match(line)
        m_wrt = re_writemem.match(line)
        m_off = re_offset.match(line)

        print(i, line, m_adr, m_wrt, m_off)

        if not m_adr is None:
            offset = 0x80000000
            new_text.append(line)
        elif not m_wrt is None:
            val = m_wrt.group(3)
        elif not m_off is None:
            if not re_writemem.match(prev) is None:
                tabs = m_off.group(1)
                for nl in write_mem(val, '{0:#x}'.format(offset)):
                    new_text.append(tabs + nl)
            else:
                new_text.append(line)
            offset += int(m_off.group(2))
        elif prev == '' and line == '':
            continue
        else:
            new_text.append(line)

        prev = line

    return new_text

def main():
    ftxt = 'testFW/offloads/tests/arpOffloadEnable.txt'
    txt = parse(read_txt(ftxt))
    for l in txt:
        print(l)

if __name__ == '__main__':
    main()
