import numpy


class IperfResult:
    SANITY = {'b': 0.0001, 'l': 0.99}
    PERFORMANCE = {'b': 0.5, 'l': 0.5}

    def __init__(self):
        self.streams = []  # array of {'bandwidth': [], 'lost': []}

        self.bandwidth = []  # array of sum bandwidth
        self.lost = []  # array of sum lost

        self.speed = 0  # 'Mbps'
        self.version = ''  # 'perf 3.1.3'
        self.client = ''  # '192.168.0.2'
        self.system = ''  # 'CYGWIN_NT-10.0 at079-h270m 2.5.1(0.297/5/3) 2016-04-21 22:14 x86_64'

    def get_metrics(self):
        metrics = [
            ("iPerf bandwidth",
             "Mbps",
             numpy.amin(self.bandwidth),
             numpy.amax(self.bandwidth),
             numpy.average(self.bandwidth),
             len(self.bandwidth)
             )
        ]

        if len(self.lost) > 0:
            metrics.append(
                ("iPerf lost",
                 "%",
                 numpy.amin(self.lost),
                 numpy.amax(self.lost),
                 numpy.average(self.lost),
                 len(self.lost)
                 )
            )

        return metrics

    def check(self, criterion=SANITY):
        b = criterion['b']
        l = criterion['l']

        assert len(self.bandwidth) > 0, 'Bandwidth can not be empty\n{}'.format(self)

        b_min = numpy.amin(self.bandwidth)
        if len(self.lost) > 0:
            l_max = numpy.amax(self.lost)

        b_mean = numpy.mean(self.bandwidth)
        if len(self.lost) > 0:
            l_mean = numpy.mean(self.lost)

        assert b_min >= 1.0, "Bandwidth can not be less 1.0 Mbps: {}".format(self.client)
        if len(self.lost) > 0:
            assert l_max <= 99.0, "Maximum of lost packages can not be more than 99.0%: {}".format(self.client)

        self.speed = 100 if self.speed == 0 else self.speed

        assert b_mean >= self.speed * b, "Mean of bandwidth must be more than linkspeed * {}: {:5.1f} >= {:5.1f}    {}".format(
            b, b_mean, self.speed * b, self.client)

        if len(self.lost) > 0:
            assert l_mean <= 100.0 * l, "Mean of lost packages can not be more than {}%: {}".format(100.0 * l,
                                                                                                    self.client)

    def get_avg_b(self):
        return numpy.average(self.bandwidth)

    def __repr__(self):
        repr_b = ', '.join(['{:.1f}'.format(e) for e in self.bandwidth])
        repr_l = ', '.join(['{:.1f}'.format(e) for e in self.lost])
        return '<s:{} b:[{}] l:[{}]>'.format(int(self.speed), repr_b, repr_l)

    def __str__(self):
        msg = '\n'

        try:
            msg += '+ REPORT: -------------------------------------------------------------------------------------- +\n'
            msg += '|  perf version: {}\n'.format(self.version)
            msg += '|         system: {}\n'.format(self.system)
            msg += '|         client: {}\n'.format(self.client)
            msg += '+ ---------------------------------------------------------------------------------------------- +\n'

            for s in self.streams:
                b_min = numpy.amin(s['bandwidth'])
                b_max = numpy.amax(s['bandwidth'])
                b_mean = numpy.mean(s['bandwidth'])

                msg += '|     bandwidths: MIN: {:7.1f} Mbps    MAX: {:7.1f} Mbps   MEAN: {:7.1f} Mbps\n'.format(b_min, b_max, b_mean)
                msg += '|     bandwidths: {} Mbps\n'.format([int(e) for e in s['bandwidth']])
                if 'lost' in s.keys() and len(s['lost']) > 0:
                    l_min = numpy.amin(s['lost'])
                    l_max = numpy.amax(s['lost'])
                    l_mean = numpy.mean(s['lost'])

                    msg += '|           lost: MIN: {:7.1f} %    MAX: {:7.1f} %   MEAN: {:7.1f} %\n'.format(l_min, l_max, l_mean)
                    msg += '|           lost: {} %\n'.format(['{:.1f}'.format(e) for e in s['lost']])
                msg += '+ ---------------------------------------------------------------------------------------------- +\n'

            p50 = numpy.quantile(self.bandwidth, 0.50)
            p70 = numpy.quantile(self.bandwidth, 0.70)
            p85 = numpy.quantile(self.bandwidth, 0.85)
            p95 = numpy.quantile(self.bandwidth, 0.95)

            b_min = numpy.amin(self.bandwidth)
            b_max = numpy.amax(self.bandwidth)
            b_mean = numpy.mean(self.bandwidth)
            b_std = numpy.std(self.bandwidth)

            msg += '| SUM bandwidths: MIN: {:7.1f} Mbps    MAX: {:7.1f} Mbps   MEAN: {:7.1f} Mbps   STD: {:7.1f}\n'.format(b_min, b_max, b_mean, b_std)
            msg += '| SUM bandwidths: p50: {:7.1f} Mbps    p70: {:7.1f} Mbps    p85: {:7.1f} Mbps   p95: {:7.1f} Mbps\n'.format(p50, p70, p85, p95)
            msg += '| SUM bandwidths: {} Mbps\n'.format([int(e) for e in self.bandwidth])

            if len(self.lost) > 0:
                self.lost = [e / float(len(self.streams)) for e in self.lost]

                p50 = numpy.quantile(self.lost, 0.50)
                p70 = numpy.quantile(self.lost, 0.70)
                p85 = numpy.quantile(self.lost, 0.85)
                p95 = numpy.quantile(self.lost, 0.95)

                l_min = numpy.amin(self.lost)
                l_max = numpy.amax(self.lost)
                l_mean = numpy.mean(self.lost)
                l_std = numpy.std(self.lost)

                msg += '|       SUM lost: MIN: {:7.1f}%    MAX: {:7.1f}%   MEAN: {:7.1f}%    STD: {:7.1f}\n'.format(l_min, l_max, l_mean, l_std)
                msg += '|       SUM lost: p50: {:7.1f}%    p70: {:7.1f}%    p85: {:7.1f}%    p95: {:7.1f}%\n'.format(p50, p70, p85, p95)
                msg += '|       SUM lost: {} %\n'.format(['{:.1f}'.format(e) for e in self.lost])
            msg += '+ ---------------------------------------------------------------------------------------------- +\n'

        except Exception as e:
            msg = '{}'.format(e)

        return msg
