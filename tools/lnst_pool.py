import json
from command import Command
from tools.utils import get_atf_logger

log = get_atf_logger()


def get_output_from_command(cmd, host):
    cmd = Command(cmd=cmd, host=host)
    result = cmd.run_join()['output']
    log.debug("   RAW: {}".format(result))
    result = result[0] if len(result) == 1 else result
    log.debug("   NEW: {}".format(result))
    return result


def get_ip_and_mac_from_machine(machine):
    cmd_ip = "ifconfig `route | grep default | awk '{print $8}' | head -n 1` | grep \"inet \" | awk '{print $2}'"
    ip = get_output_from_command(cmd_ip, host=machine)
    log.info('    IP: {}'.format(ip))
    links = get_output_from_command("ifconfig -a | grep \" flags=\" | awk '{print $1}'", host=machine)
    links = [l[:-1] for l in links]
    log.info('LINKS: {}'.format(links))

    for l in links:
        drv = get_output_from_command("ethtool -i {} | grep \"driver: atlantic\"".format(l), host=machine)
        log.info('   DRV: {}'.format(drv))
        if drv:
            mac = get_output_from_command("ifconfig {} | grep \"ether \" | awk '{{print $2}}'".format(l), host=machine)
            log.info('   MAC: {}'.format(mac))
            break

    return ip, mac


def load_map_file():
    try:
        output = get_output_from_command('cat /home/aqtest/map.json', host='lnst-master.rdc-lab.marvell.com')
    except Exception as e:
        log.exception(e)
        output = '{}'
    log.info("OUTPUT: {}".format(output))
    return json.loads(output)


def save_map_file(map_machine_file):
    cmd = 'echo "{}" > /home/aqtest/map.json'.format(json.dumps(map_machine_file).replace('"', '\\"'))
    log.info('  SAVE: {}'.format(cmd))
    get_output_from_command(cmd, host='lnst-master.rdc-lab.marvell.com')


def get_filename_machine(machine):
    map_machine_name_file = load_map_file()
    log.info("   MAP: {}".format(map_machine_name_file))

    if not machine in map_machine_name_file.keys():
        values = sorted(map_machine_name_file.values())
        log.info('VALUES: {}'.format(values))
        log.info(' MACHINE: {}'.format(machine))
        log.info('MACHINES: {}'.format(map_machine_name_file.keys()))
        map_machine_name_file[machine] = values[-1] + 1
        save_map_file(map_machine_name_file)

    machine_name = 'machine{}.xml'.format(map_machine_name_file[machine])
    log.info('  NAME: {}'.format(machine_name))
    return machine_name


def generate_xml_config(ip, mac):
    text = """<slavemachine>
    <params>
        <param name="hostname" value="{}"/>
        <param name="rpc_port" value="9999"/>
    </params>
    <interfaces>
        <eth label="A" id="1">
             <params>
                 <param name="hwaddr" value="{}"/>
             </params>
        </eth>
    </interfaces>
</slavemachine>
"""
    return text.format(ip, mac)


def save_machine_config(filename, xml_config):
    cmd = 'echo "{}" > /home/aqtest/lab/{}'.format(xml_config.replace('"', '\\"'), filename)
    log.info('  XML: {}'.format(cmd))
    get_output_from_command(cmd, host='lnst-master.rdc-lab.marvell.com')


def update_pool_file(machine, ip, mac):
    filename = get_filename_machine(machine)
    xml_config = generate_xml_config(ip, mac)
    save_machine_config(filename, xml_config)
    return filename


def update_machine_info(machine):
    ip, mac = get_ip_and_mac_from_machine(machine)
    return update_pool_file(machine, ip, mac)


def update_lnst_pool(machines):
    m = dict()
    for machine in machines:
        m[machine] = update_machine_info(machine)[:-4]
    return m

