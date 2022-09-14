import argparse
import time

from threading import Thread
from collections import namedtuple
try:
    import phyaccess
except ImportError as e:
    print(e)
    raise Exception("Can`t find phyaccess module. "
                    "To run this script you need to set Python Path to the phyaccess dir. \n "
                    "If you run script directly on BB call BBEnv.sh script. "
                    "Otherwise download latest SLT tools folder and execute setpypath from it")


board_description = namedtuple("board", ["rail_list", "voltages_map"])

JASMINE_RAIL_LIST = ["VDD", "P3V3", "P1V2", "P2V1"]
JASMINE_RAIL_VOLTAGES = {"VDD": 0.857, "P3V3": 3.3, "P1V2": 1.2, "P2V1": 2.1}
JASMINE_BOARD = board_description(JASMINE_RAIL_LIST, JASMINE_RAIL_VOLTAGES)

ANTIGUA_RAIL_LIST = ["VDD", "P3V3", "P2V0", "P1V0"]
ANTIGUA_RAIL_VOLTAGES = {"VDD": 0.7, "P3V3": 3.3, "P2V0": 2.0, "P1V0": 1.0}
ANTIGUA_BOARD = board_description(ANTIGUA_RAIL_LIST, ANTIGUA_RAIL_VOLTAGES)

KNOWN_BOARDS = {"JASMINE": JASMINE_BOARD, "ANTIGUA": ANTIGUA_BOARD}


class ResultValue(object):
    def __init__(self, time, value):
        self.time = time
        self.value = value

    def __gt__(self, other):
        return self.time > other.time

    def __ge__(self, other):
        return self.time >= other.time

    def __lt__(self, other):
        return self.time < other.time

    def __le__(self, other):
        return self.time <= other.time

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "{{'time': {}, 'value': {}}}".format(self.time, self.value)


class Rail(object):
    def __init__(self, name, board_description):
        self.allowed_rails = board_description.rail_list
        self.rail_name = None
        self.measure_voltage = False
        self.measure_current = False
        self.parse_rail_name(name)
        self.default_voltage = board_description.voltages_map[self.rail_name]

    def __str__(self):
        return '"' + self.rail_name + '"'

    def __repr__(self):
        return str(self)

    def parse_rail_name(self, name):
        rail_name = name
        current_voltage = None
        if "_" in name:
            rail_name, current_voltage = name.rsplit("_", 1)
        rail_name = rail_name.upper()
        if rail_name not in self.allowed_rails:
            raise Exception("Wrong rail name {} provided. Allowed rail name for current board: {}".format(rail_name,
                                                                                                          self.allowed_rails))
        self.rail_name = rail_name
        if current_voltage is None:
            self.measure_current = True
            self.measure_voltage = True
        elif current_voltage.upper() == "C":
            self.measure_current = True
        elif current_voltage.upper() == "V":
            self.measure_voltage = True
        else:
            raise Exception("Wrong measured parameter name. Mast be C or V got: {}".format(current_voltage))


class MeasureThread(Thread):
    def __init__(self, rail, pa, measure_time=1, log=False):
        super(MeasureThread, self).__init__()
        self.rail = rail
        self.device = pa.board.voltages.voltageDevices[self.rail.rail_name]
        self.measure_time = measure_time
        self.log = log
        self._res_voltages = []
        self._res_currents = []

    def measure(self, res, code, offset, scale, value_type):
        if code & 1 << 15:
            measure = 1.0 * (self.device.interface.ADCCodeToValue(code) - offset) * scale
            measured_time = time.time()
            res.append(ResultValue(time=measured_time, value=measure))
            if self.log:
                print("Time: {} rail: {}; {}: {}".format(measured_time, self.device.name, value_type, measure))

    def run(self):
        start_time = time.time()
        while ((time.time() - start_time) < self.measure_time):
            if self.rail.measure_current:
                self.measure(self._res_currents,
                             self.device.interface.ADCCode(self.device.currentChannel),
                             self.device.currentOffset, self.device.currentScale, "current")
            if self.rail.measure_voltage:
                self.measure(self._res_voltages,
                             self.device.interface.ADCCode(self.device.channel),
                             self.device.offset, self.device.scale, "voltage")

    def join(self):
        super(MeasureThread, self).join()
        return self.rail, {"voltage": self._res_voltages, "current": self._res_currents}


def connect_to_board(board, phy_id):
    if board is None:
        import PhyAccessBeaglebone
        import Beaglebone
        board = Beaglebone.boardSN()
        return PhyAccessBeaglebone.Direct(board, phy_id, key=0)
    else:
        return phyaccess.PhyAccess.create(board, phy_id)


def enable_board(board, rails, state=True):
    if state:
        board.enableSocket()
    else:
        board.disableSocket()


def run_join_threads(threads):
    results = {}
    for run_thread in threads:
        run_thread.start()
    for run_thread in threads:
        result = run_thread.join()
        results[result[0]] = result[1]
    return results


def avg(values):
    return(sum(values) / len(values))


def calc_averages(results):
    lengths = []
    for rail in sorted(results.keys()):
        currents = [curr.value for curr in results[rail]["current"]]
        if not len(currents):
            continue
        lengths.append(len(currents))
        min_c = min(currents)
        min_p = min_c * rail.default_voltage
        max_c = max(currents)
        max_p = max_c * rail.default_voltage
        avg_c = avg(currents)
        avg_p = avg_c * rail.default_voltage
        print("Rail {}: \n    Current. Min: {}, Max: {}, Avg: {}.\n    Power. Min: {}, Max: {}, Avg: {}\n"\
            .format(rail, min_c, max_c, avg_c, min_p, max_p, avg_p))
    if not lengths:
        print("No currents measured. Statistic wouldn`t be printed.")
        return
    min_len = min(lengths)
    sum_currents = []
    sum_power = []
    for i in range(min_len):
        one_time_sum_curr = 0
        one_time_sum_pwr = 0
        for rail in results.keys():
            one_time_sum_curr += results[rail]["current"][i].value
            one_time_sum_pwr += results[rail]["current"][i].value * rail.default_voltage
        sum_currents.append(one_time_sum_curr)
        sum_power.append(one_time_sum_pwr)

    sum_min_c = min(sum_currents)
    sum_max_c = max(sum_currents)
    sum_avg_c = avg(sum_currents)
    sum_min_p = min(sum_power)
    sum_max_p = max(sum_power)
    sum_avg_p = avg(sum_power)
    print("Summary: \n    Current. Min: {}, Max: {}, Avg: {}.\n    Power. Min: {}, Max: {}, Avg: {}\n"\
          .format(sum_min_c, sum_max_c, sum_avg_c, sum_min_p, sum_max_p, sum_avg_p))


def dump_results_to_file(results, file):
    with open(args.file +".txt", "w+") as f:
        f.write(str(results).replace("'", "\""))


def fill_voltages(results):
    """Fill voltages value with default voltage to results JSON
    if voltages was not captured during measurment
    """
    for rail in results:
        if len(results[rail]["voltage"]) == 0:
            results[rail]["voltage"] = [ResultValue(res.time, rail.default_voltage) for res in results[rail]["current"]]


def get_rails(pa, requsted_rails):
    rails = []
    if hasattr(pa.board.type, "DUTboardType"):
        dev_id = pa.board.type.DUTboardType.id
    else:
        dev_id = pa.board.type.id
    dev_id = dev_id.lower()

    for known_board in KNOWN_BOARDS.keys():
        if known_board.lower() in dev_id:
            print("Found known board: {}".format(known_board))
            if len(requsted_rails) == 0:
                print("No rails for measure provided. All available rails for board will be selected automatically")
                requsted_rails = KNOWN_BOARDS[known_board].rail_list
            rails = [Rail(rail, board_description=KNOWN_BOARDS[known_board]) for rail in requsted_rails]
            break
    else:
        raise RuntimeError("Unknow board type: {}.\n List of known boards: {}".format(dev_id,
                                                                                      KNOWN_BOARDS.keys()))
    return rails

def main(args):
    pa = connect_to_board(args.board, args.phyid)
    rails = get_rails(pa, requsted_rails=args.rails)
    if args.enable:
        enable_board(pa.board, rails)
    try:
        measure_threads = [MeasureThread(rail, pa, measure_time=args.time, log=True) for rail in rails]
        results = run_join_threads(measure_threads)
    finally:
        if args.enable:
            enable_board(pa.board, rails, state=False)
    fill_voltages(results)
    dump_results_to_file(results, args.file)
    calc_averages(results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--time", help="Measure time", type=int, default=1)
    parser.add_argument('-i', '--phyid', default=0, help="Phy ID. For boards with mdio-over-smbus, this is the smbus address.")
    parser.add_argument("-r", "--rails", nargs='+',
                        help='measure rails. example "VDD_C P1V3_V P2V1". rail name without params - measure both current and voltage values',
                        default="")
    parser.add_argument("-b", "--board", help="board name", type=str, required=False)
    parser.add_argument("-e", "--enable", help="Enable rails on board", action='store_true')
    parser.add_argument("-f", "--file", help="file to save results", type=str, required=False,
                        default=time.strftime("%Y%m%d_%H%M", time.localtime()))
    args = parser.parse_args()
    main(args)
