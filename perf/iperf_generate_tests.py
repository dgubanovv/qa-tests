t = {}
t[0] = 'LINK_SPEED_AUTO'
t[10] = 'LINK_SPEED_10M'
t[100] = 'LINK_SPEED_100M'
t[1000] = 'LINK_SPEED_1G'
t[2500] = 'LINK_SPEED_2_5G'
t[5000] = 'LINK_SPEED_5G'
t[10000] = 'LINK_SPEED_10G'

dd = {}
dd['rxtx'] = 'DIRECTION_RXTX'
dd['rx'] = 'DIRECTION_RX'
dd['tx'] = 'DIRECTION_TX'

dp = {}
dp['full'] = "DUPLEX_FULL"
dp['half'] = "DUPLEX_HALF"


def write_template(is_udp, is_eee, tests):
    with open('iperf.template', 'r') as f:
        text = f.readlines()
        text = ''.join(text)

    text = text.replace('#@tests', ''.join(tests))

    name = 'iperf'
    name += '_udp' if is_udp else '_tcp'
    name += '_eee' if is_eee else ''
    name += '.py'

    print('write: {}'.format(name))

    with open(name, 'w') as f:
        f.write(text)

    print('done.')


def gen_test(conf, buff=None, name_test=None):
    result = []

    # def test_iperf_udp_100m_rxtx_n1_v4_l65500_fc(self):
    if name_test is not None:
        msg = "    def test_{}(self):\n".format(name_test)
    else:
        name = conf['type'] + ('_eee' if conf['eee'] else '')
        msg = '    def test_iperf_{}'.format(name)
        msg += '_{}m'.format(conf['speed'])
        msg += '_{}_duplex'.format(conf['duplex'])
        msg += '_{}_p{}_t{}'.format(conf['direction'], conf['process'], conf['threads'])
        msg += '_v{}'.format(conf['ipv'])
        msg += '_l{}'.format(conf['buffer_len']) if conf['buffer_len'] > 0 else ''
        msg += '' if conf['window'] == 0 else '_w{}'.format(str(conf['window']).replace('"', ''))
        msg += '_fc' if conf['fc'] else ''
        msg += '(self):\n'

    print (msg[:-1])
    result.append(msg)

    is_udp = 'True' if conf['type'] == 'udp' else 'False'
    is_eee = 'True' if conf['eee'] else 'False'
    is_fc = 'True' if conf['fc'] else 'False'

    is_perf = 'IperfResult.SANITY'
    if 'test' in conf.keys():
        is_perf = 'IperfResult.PERFORMANCE' if conf['test'] == 'perf' else 'IperfResult.SANITY'

    time = 183 if conf['eee'] else 17
    if 'time' in conf.keys():
        time = conf['time']
    if buff is not None:
        result.append(buff)
        result.append("\n")

    msg = "        args = {\n"
    msg += "            'direction': {},\n".format(dd[conf['direction']])
    msg += "            'speed': {},\n".format(t[conf['speed']])
    msg += "            'duplex': {},\n".format(dp[conf["duplex"]])
    msg += "            'num_process': {},\n".format(conf['process'])
    msg += "            'num_threads': {},\n".format(conf['threads'])
    msg += "            'time': {},\n".format(time)
    msg += "            'ipv': {},\n".format(conf['ipv'])
    msg += "            'mss': {},\n".format(conf['mss'])
    msg += "            'bandwidth': {},\n".format(conf['bandwidth'])
    msg += "            'buffer_len': {},\n".format(conf['buffer_len'])
    msg += "            'window': {},\n".format(conf['window'])
    msg += "            'is_udp': {},\n".format(is_udp)
    msg += "            'is_eee': {},\n".format(is_eee)
    msg += "            'is_fc': {},\n".format(is_fc)
    msg += "            'criterion': {},\n".format(is_perf)
    msg += "            'lkp': self.lkp_hostname,\n"
    msg += "            'dut': self.dut_hostname,\n"
    msg += "            'lkp4': self.LKP_IPV4_ADDR,\n"
    msg += "            'dut4': self.DUT_IPV4_ADDR,\n"
    msg += "            'lkp6': self.LKP_IPV6_ADDR,\n"
    msg += "            'dut6': self.DUT_IPV6_ADDR,\n"
    msg += "        }\n"
    msg += "        self.iperf(**args)\n\n"

    result.append(msg)
    return result


def gen_iperf_udp_test():
    count = 0

    flow_control = [True, False]
    directions = ['rxtx', 'tx', 'rx']
    speeds = [10000, 5000, 2500, 1000, 100, 10]
    duplex = ["half", "full"]
    process_and_threads = [(1, 1), (4, 1)]
    wins = ['"128k"', 0]

    tests = []
    ipv = 4

    for s in speeds:
        for dup in duplex:
            for d in directions:
                for (p, t) in process_and_threads:
                    for w in wins:
                        for f in flow_control:
                            if dup == 'half' and s > 1000:
                                continue

                            if s < 5000 and p == 4:
                                continue

                            if s != 5000 and d != 'rxtx':
                                continue

                            if s == 1000 and f == True:
                                continue

                            if (s == 2500 or s == 100) and p == 4:
                                continue

                            if f == True and p == 1:
                                continue

                            conf = {
                                'speed': s,
                                'duplex': dup,
                                'threads': t,
                                'process': p,
                                'buffer_len': 0,
                                'window': w,
                                'bandwidth': s,
                                'mss': 0,
                                'ipv': ipv,
                                'type': 'udp',
                                'eee': False,
                                'direction': d,
                                'fc': f
                            }

                            for line in gen_test(conf):
                                tests.append(line)
                            tests.append('')

                            count += 1

    ipv = 6

    for f in [True, False]:
        conf = {
            'speed': 1000,
            'duplex': "full",
            'threads': 1,
            'process': 1,
            'buffer_len': 0,
            'bandwidth': 1000,
            'window': 0,
            'mss': 0,
            'ipv': ipv,
            'type': 'udp',
            'eee': False,
            'direction': 'rxtx',
            'fc': f
        }

        for line in gen_test(conf):
            tests.append(line)
        tests.append('')

        count += 1

    buff = """        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)"""
    for s in [5000, 10000]:
        conf = {
            'speed': s,
            'duplex': "full",
            'threads': 1,
            'process': 1,
            'buffer_len': 1300,
            'window': 0,
            'bandwidth': 1000,
            'mss': 0,
            'ipv': ipv,
            'type': "udp",
            'eee': False,
            'direction': "rxtx",
            'fc': True
        }

        for line in gen_test(conf, buff):
            tests.append(line)
        tests.append('')

        count += 1

    # ---------------------------------------

    # conf = {
    #     'speed': 5000,
    #     'threads': 1,
    #     'process': 16,
    #     'buffer_len': 0,
    #     'bandwidth': 0,
    #     'window': '"8k"',
    #     'mss': 0,
    #     'ipv': 4,
    #     'type': 'udp',
    #     'eee': False,
    #     'direction': 'rx',
    #     'fc': False
    # }
    #
    # for line in gen_test(conf):
    #     tests.append(line)
    # tests.append('')
    #
    # count += 1

    tests.append('    # total tests: {}\n'.format(count))
    print('total tests: {}\n'.format(count))
    return tests


def gen_iperf_tcp_test():
    count = 0

    type_ip = 'tcp'

    flow_control = [True, False]
    directions = ['rxtx', 'tx', 'rx']
    speeds = [10000, 5000, 2500, 1000, 100, 10]
    duplex = ["full","half"]
    process_and_threads = [(1, 1), (1, 4)]
    wins = ['"8k"', 0]

    tests = []
    ipv = 4

    for s in speeds:
        for dup in duplex:
            for d in directions:
                for (p, t) in process_and_threads:
                    for w in wins:
                        for f in flow_control:

                            if s in [100, 1000, 2500] and (p > 1 or t > 1):
                                continue

                            if s in [100, 1000, 2500] and f is True:
                                continue

                            if dup == "half" and s > 1000:
                                continue

                            conf = {
                                'speed': s,
                                'duplex': dup,
                                'threads': t,
                                'process': p,
                                'buffer_len': 0,
                                'window': w,
                                'bandwidth': 0,
                                'mss': 0,
                                'ipv': ipv,
                                'type': type_ip,
                                'eee': False,
                                'direction': d,
                                'fc': f
                            }

                            for line in gen_test(conf):
                                tests.append(line)
                            tests.append('')

                            count += 1

    ipv = 6

    for f in [True, False]:
        conf = {
            'speed': 1000,
            'duplex': "full",
            'threads': 1,
            'process': 1,
            'buffer_len': 1000,
            'bandwidth': 0,
            'window': 0,
            'mss': 0,
            'ipv': ipv,
            'type': 'tcp',
            'eee': False,
            'direction': 'rxtx',
            'fc': f
        }

        for line in gen_test(conf):
            tests.append(line)
        tests.append('')

        count += 1
    buff = """        self.dut_ifconfig.set_mtu(MTU_9000)
        self.lkp_ifconfig.set_mtu(MTU_9000)"""

    for s in speeds:
        conf = {
            'speed': s,
            'duplex': "full",
            'threads': 1,
            'process': 1,
            'buffer_len': 1000,
            'window': 0,
            'bandwidth': 0,
            'mss': 0,
            'ipv': 4,
            'type': "tcp",
            'eee': False,
            'direction': "rxtx",
            'fc': True
        }

        for line in gen_test(conf, buff):
            tests.append(line)
        tests.append('')

        count += 1

    windows = ['"5k"', '"10k"']
    for w in windows:
        conf = {
            'speed': 1000,
            'duplex': "full",
            'threads': 1,
            'process': 1,
            'buffer_len': 1000,
            'window': w,
            'bandwidth': 0,
            'mss': 0,
            'ipv': 4,
            'type': "tcp",
            'eee': False,
            'direction': "rxtx",
            'fc': True
        }

        for line in gen_test(conf, buff):
            tests.append(line)
        tests.append('')

        count += 1
    # ---------------------------------------

    workaround_checksum_test = """    @idparametrize("mtu", [MTU_1500, MTU_2000, MTU_4000, MTU_9000, MTU_16000])
    def test_workaround_checksum(self, mtu):
        if self.dut_fw_card in CARD_FIJI or self.lkp_fw_card in CARD_FIJI:
            pytest.skip("Skip for Fiji")

        self.dut_ifconfig.set_mtu(mtu)
        self.lkp_ifconfig.set_mtu(mtu)

        CHECKSUM = "checksum"
        LSO = "lso"
        LRO = 'lro'
        OFFLOADS_LKP = [CHECKSUM, LSO]
        
        def select_offload(ops, map_ofl, offload_name):
            if ops.is_windows():
                return map_ofl["Windows"][offload_name]
            elif ops.is_linux():
                return map_ofl["Linux"][offload_name]
            elif ops.is_freebsd():
                return map_ofl["FreeBSD"][offload_name]
        
        def get_offload_for_os(offload_name):
            map_ofl = {"Windows": {CHECKSUM: ["*TCPUDPChecksumOffloadIPv4", "*TCPUDPChecksumOffloadIPv6",
                                              "*IPChecksumOffloadIPv4", "*TCPChecksumOffloadIPv4",
                                              "*UDPChecksumOffloadIPv4", "*TCPChecksumOffloadIPv6",
                                              "*UDPChecksumOffloadIPv6"],
                                   LSO: ["*LsoV1IPv4", "*LsoV2IPv4", "*LsoV2IPv6"],
                                   LRO: [None]},

                       "Linux": {CHECKSUM: ["tx", "rx"],
                                 LSO: ["tso"],
                                 LRO: ["lro"]},
                       "FreeBSD": {CHECKSUM: ["txcsum", "rxcsum"],
                                   LSO: ["lso"],}
                                 }
            if offload_name == LRO:
                offload = select_offload(self.dut_ops, map_ofl, offload_name)
            else:
                offload = select_offload(self.lkp_ops, map_ofl, offload_name)
            return offload

        for offload in OFFLOADS_LKP:
            for offload_name in get_offload_for_os(offload):
                self.lkp_ifconfig.manage_offloads(offload_name, OFFLOADS_STATE_DSBL)
        for offload_name in get_offload_for_os(LRO):
            if offload_name is not None:
                self.dut_ifconfig.manage_offloads(offload_name, OFFLOADS_STATE_ENBL)

        args = {
            'direction': DIRECTION_RX,
            'speed': LINK_SPEED_1G,
            'duplex': DUPLEX_FULL,
            'num_process': 1,
            'num_threads': 1,
            'time': 17,
            'ipv': 6,
            'mss': 0,
            'bandwidth': 0,
            'buffer_len': 1000,
            'window': 0,
            'is_udp': False,
            'is_eee': False,
            'is_fc': False,
            'criterion': IperfResult.SANITY,
            'lkp': self.lkp_hostname,
            'dut': self.dut_hostname,
            'lkp4': self.LKP_IPV4_ADDR,
            'dut4': self.DUT_IPV4_ADDR,
            'lkp6': self.LKP_IPV6_ADDR,
            'dut6': self.DUT_IPV6_ADDR,
        }

        self.iperf(**args)\n\n"""

    for line in workaround_checksum_test:
        tests.append(line)
    tests.append('')

    count += 5
    # ---------------------------------------

    # conf = {
    #     'speed': 5000,
    #     'threads': 1,
    #     'process': 16,
    #     'buffer_len': 0,
    #     'bandwidth': 0,
    #     'window': '"8k"',
    #     'mss': 0,
    #     'ipv': 4,
    #     'type': 'tcp',
    #     'eee': False,
    #     'direction': 'rx',
    #     'fc': False
    # }
    #
    # for line in gen_test(conf):
    #     tests.append(line)
    # tests.append('')
    #
    # count += 1

    tests.append('    # total tests: {}\n'.format(count))
    print('total tests: {}\n'.format(count))
    return tests


def gen_iperf_tcp_eee_test():
    count = 0

    type_ip = 'tcp'

    directions = ['rxtx']
    speeds = [10000, 5000, 2500, 1000]
    process_and_threads = [(1, 4)]
    wins = ['"8k"', '"4k"', 0]
    duplex = ["full", "half"]

    tests = []
    ipv = 4

    for s in speeds:
        for dup in duplex:
            for d in directions:
                for (p, t) in process_and_threads:
                    for w in wins:
                        if s > 1000 and dup == "half":
                            continue

                        conf = {
                            'speed': s,
                            'duplex': dup,
                            'threads': t,
                            'process': p,
                            'buffer_len': 0,
                            'window': w,
                            'bandwidth': 0,
                            'mss': 0,
                            'ipv': ipv,
                            'type': type_ip,
                            'eee': True,
                            'direction': d,
                            'fc': True
                        }

                        for line in gen_test(conf):
                            tests.append(line)
                        tests.append('')

                        count += 1

    # ---------------------------------------

    # conf = {
    #     'speed': 5000,
    #     'threads': 1,
    #     'process': 16,
    #     'buffer_len': 0,
    #     'bandwidth': 0,
    #     'window': '"8k"',
    #     'mss': 0,
    #     'ipv': 4,
    #     'type': 'tcp',
    #     'eee': True,
    #     'direction': 'rx',
    #     'fc': False
    # }
    #
    # for line in gen_test(conf):
    #     tests.append(line)
    # tests.append('')
    #
    # count += 1

    tests.append('    # total tests: {}\n'.format(count))
    print('total tests: {}\n'.format(count))
    return tests


def gen_iperf_udp_eee_test():
    count = 0

    type_ip = 'udp'

    directions = ['rxtx']
    speeds = [10000, 5000, 2500, 1000]
    process_and_threads = [(1, 1), (4, 1)]
    pkt_lengths = [0, 100, 200]
    duplex = ["full", "half"]

    tests = []
    ipv = 4

    for s in speeds:
        for dup in duplex:
            for d in directions:
                for (p, t) in process_and_threads:
                    for pkt_len in pkt_lengths:
                        if s > 1000 and dup == "half":
                            continue

                        conf = {
                            'speed': s,
                            'duplex': dup,
                            'threads': t,
                            'process': p,
                            'window': 0,
                            'bandwidth': s,
                            'buffer_len': pkt_len,
                            'mss': 0,
                            'ipv': ipv,
                            'type': type_ip,
                            'eee': True,
                            'direction': d,
                            'fc': True
                        }

                        for line in gen_test(conf):
                            tests.append(line)
                        tests.append('')

                        count += 1
    conf = {
        'speed': 1000,
        'duplex': "full",
        'threads': 1,
        'process': 1,
        'window': 0,
        'bandwidth': 1000,
        'buffer_len': 30,
        'mss': 0,
        'ipv': ipv,
        'type': type_ip,
        'eee': True,
        'direction': "rxtx",
        'fc': True
    }

    for line in gen_test(conf):
        tests.append(line)
    tests.append('')
    count += 1

    # ---------------------------------------

    # conf = {
    #     'speed': 5000,
    #     'threads': 1,
    #     'process': 16,
    #     'buffer_len': 0,
    #     'bandwidth': (s / 4),
    #     'window': '"8k"',
    #     'mss': 0,
    #     'ipv': 4,
    #     'type': 'tcp',
    #     'eee': True,
    #     'direction': 'rx',
    #     'fc': False
    # }
    #
    # for line in gen_test(conf):
    #     tests.append(line)
    # tests.append('')
    #
    # count += 1

    tests.append('    # total tests: {}\n'.format(count))
    print('total tests: {}\n'.format(count))
    return tests


def gen_iperf_stable():
    count = 0
    tests = []

    for t in ['udp', 'tcp']:
        for s in [10000, 5000, 2500, 1000]:
            for np, nt in [(1, 1), (4, 1)]:
                for w in [0, '8M']:
                    for f in [True]:

                        if t == 'udp' and nt > 1:
                            continue

                        if s == 100 and np > 1:
                            continue

                        conf = {
                            'speed': s,
                            'duplex': "full",
                            'threads': nt,
                            'process': np,
                            'ipv': 4,
                            'time': 314,
                            'buffer_len': 0,
                            'bandwidth': 0,
                            'mss': 0,
                            'window': w,
                            'type': t,
                            'eee': False,
                            'direction': 'rxtx',
                            'test': 'perf',
                            'fc': f
                        }

                        if np == 1 and s == 1000:
                            conf['eee'] = True

                        for line in gen_test(conf):
                            tests.append(line)
                        tests.append('')
                        count += 1

    # for t in ['udp', 'tcp']:
    #     conf = {
    #         'speed': 5000,
    #         'threads': 1,
    #         'process': 16,
    #         'ipv': 6,
    #         'time': 314,
    #         'buffer_len': 0,
    #         'bandwidth': 0,
    #         'mss': 0,
    #         'window': ''"8M"'',
    #         'type': t,
    #         'eee': False,
    #         'direction': 'rxtx',
    #         'test': 'perf',
    #         'fc': True
    #     }
    #
    #     for line in gen_test(conf):
    #         tests.append(line)
    #     tests.append('')
    #     count += 1

    print('\n\n# count: {} '.format(count))
    return tests


if __name__ == '__main__':
    # write_template(is_udp=False, is_eee=False, tests=gen_iperf_tcp_test())
    # write_template(is_udp=True, is_eee=False, tests=gen_iperf_udp_test())
    #
    # write_template(is_udp=False, is_eee=True, tests=gen_iperf_tcp_eee_test())
    # write_template(is_udp=True, is_eee=True, tests=gen_iperf_udp_eee_test())
    #
    # for line in gen_iperf_stable():
    #    print (line)
    pass
