import os

patch = """
/* ============================= Python ============================= */

#include <unistd.h>

#include <cmdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>

static PyObject *DpdkError; // Python exception

extern cmdline_parse_ctx_t main_ctx[];

static char *flowtype_to_str(uint16_t flow_type)
{
    struct flow_type_info {
        char str[32];
        uint16_t ftype;
    };

    uint8_t i;
    static struct flow_type_info flowtype_str_table[] = {
        {"raw", RTE_ETH_FLOW_RAW},
        {"ipv4", RTE_ETH_FLOW_IPV4},
        {"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
        {"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
        {"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
        {"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
        {"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
        {"ipv6", RTE_ETH_FLOW_IPV6},
        {"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
        {"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
        {"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
        {"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
        {"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
        {"l2_payload", RTE_ETH_FLOW_L2_PAYLOAD},
        {"port", RTE_ETH_FLOW_PORT},
        {"vxlan", RTE_ETH_FLOW_VXLAN},
        {"geneve", RTE_ETH_FLOW_GENEVE},
        {"nvgre", RTE_ETH_FLOW_NVGRE},
        {"vxlan-gpe", RTE_ETH_FLOW_VXLAN_GPE},
    };

    for (i = 0; i < RTE_DIM(flowtype_str_table); i++) {
        if (flowtype_str_table[i].ftype == flow_type)
            return flowtype_str_table[i].str;
    }

    return NULL;
}

#define CHECK_PORT_ID(port_id) \\
    if (port_id_is_invalid(port_id, ENABLED_WARN)) { \\
        PyErr_Format(DpdkError, "Port %d is invalid", port_id); \\
        return NULL; \\
    }

static PyObject *get_valid_ports(PyObject* self, PyObject* args)
{
    portid_t pid;

    PyObject* res;

    res = PyList_New(0);

    RTE_ETH_FOREACH_DEV(pid) {
        PyList_Append(res, PyInt_FromLong(pid));
    }

    return res;
}

static PyObject *exec_cmd(PyObject* self, PyObject* args)
{
    char *cmd;
    int cmdLen;
    char *buff;
    struct cmdline *cl;

    if (!PyArg_ParseTuple(args, "s#", &cmd, &cmdLen))
        return NULL;

    buff = malloc(cmdLen + 2);
    strcpy(buff, cmd);
    buff[cmdLen] = '\\n';
    buff[cmdLen + 1] = '\\0';

    cl = cmdline_new(main_ctx, "", 0, 0);
    if (cl == NULL) {
        PyErr_SetString(DpdkError, "Failed to create cmdline context");
        free(buff);
        return NULL;
    }
    cmdline_in(cl, buff, cmdLen + 1);
    cmdline_poll(cl);
    cmdline_quit(cl);
    cmdline_free(cl);

    free(buff);

    Py_RETURN_NONE;
}

static PyObject *show_port_info(PyObject* self, PyObject* args)
{
    uint16_t port_id;
    struct rte_port *port;
    struct ether_addr mac_addr;
    struct rte_eth_link link;
    struct rte_eth_dev_info dev_info;
    int vlan_offload;
    struct rte_mempool * mp;
    uint16_t mtu;
    char name[RTE_ETH_NAME_MAX_LEN];
    char mac_buf[ETHER_ADDR_FMT_SIZE];

    PyObject *res = NULL;
    PyObject *vlan_offload_dict = NULL;
    PyObject *switch_dict = NULL;
    PyObject *flow_types_list = NULL;

    if (!PyArg_ParseTuple(args, "H", &port_id))
        return NULL;

    CHECK_PORT_ID(port_id);

    res = PyDict_New();

    port = &ports[port_id];

    memset(&link, 0, sizeof(link));
    rte_eth_link_get_nowait(port_id, &link);
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);

    rte_eth_macaddr_get(port_id, &mac_addr);
    ether_format_addr(mac_buf, ETHER_ADDR_FMT_SIZE, &mac_addr);
    PyDict_SetItemString(res, "mac_address", PyString_FromString(mac_buf));

    rte_eth_dev_get_name_by_port(port_id, name);
    PyDict_SetItemString(res, "device_name", PyString_FromString(name));
    PyDict_SetItemString(res, "driver_name", PyString_FromString(dev_info.driver_name));
    PyDict_SetItemString(res, "socket_id", PyInt_FromLong(port->socket_id));

    if (port_numa[port_id] != NUMA_NO_CONFIG) {
        mp = mbuf_pool_find(port_numa[port_id]);
        if (mp) {
            PyDict_SetItemString(res, "mem_alloc_socket", PyInt_FromLong(port_numa[port_id]));
        } else {
            PyDict_SetItemString(res, "mem_alloc_socket", Py_None);
        }
    } else {
        PyDict_SetItemString(res, "mem_alloc_socket", PyInt_FromLong(port->socket_id));
    }

    PyDict_SetItemString(res, "link_status", (link.link_status == ETH_LINK_UP) ? (Py_True) : (Py_False));
    PyDict_SetItemString(res, "link_speed", PyInt_FromLong(link.link_speed));
    PyDict_SetItemString(res, "link_duplex", PyString_FromString((link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full") : ("half")));
    PyDict_SetItemString(res, "link_autoneg", (link.link_autoneg == ETH_LINK_AUTONEG) ? (Py_True) : (Py_False));

    PyDict_SetItemString(res, "mtu", (!rte_eth_dev_get_mtu(port_id, &mtu)) ? PyInt_FromLong(mtu) : Py_None);

    PyDict_SetItemString(res, "promiscuous_mode", rte_eth_promiscuous_get(port_id) ? Py_True : Py_False);
    PyDict_SetItemString(res, "allmulticast_mode", rte_eth_allmulticast_get(port_id) ? Py_True : Py_False);
    PyDict_SetItemString(res, "max_mac_addr", PyInt_FromLong((unsigned int)(port->dev_info.max_mac_addrs)));
    PyDict_SetItemString(res, "max_mac_addr_hash_filtering", PyInt_FromLong((unsigned int)(port->dev_info.max_hash_mac_addrs)));

    vlan_offload_dict = PyDict_New();
    PyDict_SetItemString(res, "vlan_offload", vlan_offload_dict);
    vlan_offload = rte_eth_dev_get_vlan_offload(port_id);
    if (vlan_offload >= 0) {
        PyDict_SetItemString(vlan_offload_dict, "strip", (vlan_offload & ETH_VLAN_STRIP_OFFLOAD) ? Py_True : Py_False);
        PyDict_SetItemString(vlan_offload_dict, "filter", (vlan_offload & ETH_VLAN_FILTER_OFFLOAD) ? Py_True : Py_False);
        PyDict_SetItemString(vlan_offload_dict, "qinq(extend)", (vlan_offload & ETH_VLAN_EXTEND_OFFLOAD) ? Py_True : Py_False);
    }

    PyDict_SetItemString(res, "hash_key_size", PyInt_FromLong(dev_info.hash_key_size));
    PyDict_SetItemString(res, "redirection_table_size", PyInt_FromLong(dev_info.reta_size));

    flow_types_list = PyList_New(0);
    PyDict_SetItemString(res, "flow_types", flow_types_list);
    if (dev_info.flow_type_rss_offloads) {
        uint16_t i;
        char *p;

        for (i = RTE_ETH_FLOW_UNKNOWN + 1; i < sizeof(dev_info.flow_type_rss_offloads) * CHAR_BIT; i++) {
            if (!(dev_info.flow_type_rss_offloads & (1ULL << i)))
                continue;
            p = flowtype_to_str(i);
            if (p) {
                PyList_Append(flow_types_list, PyString_FromString(p));
            } else {
                PyList_Append(flow_types_list, PyString_FromFormat("user defined %d", i));
            }
        }
    }

    PyDict_SetItemString(res, "min_rx_bufsize", PyInt_FromLong(dev_info.min_rx_bufsize));
    PyDict_SetItemString(res, "max_rx_pktlen", PyInt_FromLong(dev_info.max_rx_pktlen));
    PyDict_SetItemString(res, "max_vfs", PyInt_FromLong(dev_info.max_vfs));
    PyDict_SetItemString(res, "max_vmdq_pools", PyInt_FromLong(dev_info.max_vmdq_pools));

    PyDict_SetItemString(res, "nb_rx_queues", PyInt_FromLong(dev_info.nb_rx_queues));
    PyDict_SetItemString(res, "max_rx_queues", PyInt_FromLong(dev_info.max_rx_queues));
    PyDict_SetItemString(res, "max_rx_desc_per_queue", PyInt_FromLong(dev_info.rx_desc_lim.nb_max));
    PyDict_SetItemString(res, "min_rx_desc_per_queue", PyInt_FromLong(dev_info.rx_desc_lim.nb_min));
    PyDict_SetItemString(res, "rx_desc_nb_align", PyInt_FromLong(dev_info.rx_desc_lim.nb_align));

    PyDict_SetItemString(res, "nb_tx_queues", PyInt_FromLong(dev_info.nb_tx_queues));
    PyDict_SetItemString(res, "max_tx_queues", PyInt_FromLong(dev_info.max_tx_queues));
    PyDict_SetItemString(res, "max_tx_desc_per_queue", PyInt_FromLong(dev_info.tx_desc_lim.nb_max));
    PyDict_SetItemString(res, "min_tx_desc_per_queue", PyInt_FromLong(dev_info.tx_desc_lim.nb_min));
    PyDict_SetItemString(res, "tx_desc_nb_align", PyInt_FromLong(dev_info.tx_desc_lim.nb_align));

    /* Show switch info only if valid switch domain and port id is set */
    switch_dict = PyDict_New();
    PyDict_SetItemString(res, "switch", switch_dict);
    if (dev_info.switch_info.domain_id != RTE_ETH_DEV_SWITCH_DOMAIN_ID_INVALID) {
        PyDict_SetItemString(switch_dict, "name", PyString_FromString(dev_info.switch_info.name));
        PyDict_SetItemString(switch_dict, "domain_id", PyInt_FromLong(dev_info.switch_info.domain_id));
        PyDict_SetItemString(switch_dict, "port_id", PyInt_FromLong(dev_info.switch_info.port_id));
    }

    return res;
}

static PyObject *show_port_stats(PyObject* self, PyObject* args)
{
    uint16_t port_id;
    struct rte_eth_stats stats;
    PyObject* res = NULL;

    if (!PyArg_ParseTuple(args, "H", &port_id))
        return NULL;

    CHECK_PORT_ID(port_id);

    rte_eth_stats_get(port_id, &stats);

    res = PyDict_New();

    PyDict_SetItemString(res, "rx_good_packets", PyLong_FromUnsignedLongLong(stats.ipackets));
    PyDict_SetItemString(res, "tx_good_packets", PyLong_FromUnsignedLongLong(stats.opackets));
    PyDict_SetItemString(res, "rx_good_bytes", PyLong_FromUnsignedLongLong(stats.ibytes));
    PyDict_SetItemString(res, "tx_good_bytes", PyLong_FromUnsignedLongLong(stats.obytes));
    PyDict_SetItemString(res, "rx_missed_errors", PyLong_FromUnsignedLongLong(stats.imissed));
    PyDict_SetItemString(res, "rx_errors", PyLong_FromUnsignedLongLong(stats.ierrors));
    PyDict_SetItemString(res, "tx_errors", PyLong_FromUnsignedLongLong(stats.oerrors));
    PyDict_SetItemString(res, "rx_mbuf_allocation_errors", PyLong_FromUnsignedLongLong(stats.rx_nombuf));

    return res;
}

static PyObject *show_ports_info(PyObject* self, PyObject* args)
{
    PyObject* res = NULL;
    res = PyDict_New();

    PyDict_SetItemString(res, "count_avail", PyLong_FromUnsignedLongLong(rte_eth_dev_count_avail()));

    return res;
}

static PyObject *parse_args(PyObject* self, PyObject* args)
{
    int argc = 0;
    char ** argv = NULL;
    char buff[8192] = {0,};

    PyObject *pList;
    PyObject *strObj;
    long int i, n = 0;

    if (!PyArg_ParseTuple(args, "O!", &PyList_Type, &pList)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be a list.");
        return NULL;
    }

    argc = PyList_Size(pList);
    argv = malloc(sizeof(argv) * argc);

    for (i = 0; i < argc; i++) {
        strObj = PyList_GetItem(pList, i); /* Can't fail */
        PyString_AsStringAndSize(strObj, &buff, &n);
        argv[i] = malloc(n + 1);
        strcpy(argv[i], PyString_AsString(strObj));
        argv[i][n] = '\\0';
    }

    launch_args_parse(argc, argv);

    for (i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);

    Py_RETURN_NONE;
}

static PyObject *show_port_xstats(PyObject* self, PyObject* args)
{
    uint16_t port_id;
    struct rte_eth_xstat *xstats;
    int cnt_xstats, idx_xstat;
    struct rte_eth_xstat_name *xstats_names;
    PyObject* res = NULL;

    if (!PyArg_ParseTuple(args, "H", &port_id))
        return NULL;

    CHECK_PORT_ID(port_id);

    cnt_xstats = rte_eth_xstats_get_names(port_id, NULL, 0);
    if (cnt_xstats < 0) {
        PyErr_SetString(DpdkError, "Error: Cannot get count of xstats");
        return NULL;
    }

    xstats_names = malloc(sizeof(struct rte_eth_xstat_name) * cnt_xstats);
    if (cnt_xstats != rte_eth_xstats_get_names(port_id, xstats_names, cnt_xstats)) {
        PyErr_SetString(DpdkError, "Error: Cannot get xstats lookup");
        free(xstats_names);
        return NULL;
    }

    xstats = malloc(sizeof(struct rte_eth_xstat) * cnt_xstats);
    if (cnt_xstats != rte_eth_xstats_get(port_id, xstats, cnt_xstats)) {
        PyErr_SetString(DpdkError, "Error: Unable to get xstats");
        free(xstats_names);
        free(xstats);
        return NULL;
    }

    res = PyDict_New();
    for (idx_xstat = 0; idx_xstat < cnt_xstats; idx_xstat++) {
        PyDict_SetItemString(res, xstats_names[idx_xstat].name, PyLong_FromUnsignedLongLong(xstats[idx_xstat].value));
    }
    free(xstats_names);
    free(xstats);

    return res;
}

static PyObject *clear_port_stats(PyObject* self, PyObject* args)
{
    uint16_t port_id;

    if (!PyArg_ParseTuple(args, "H", &port_id))
        return NULL;

    CHECK_PORT_ID(port_id);

    rte_eth_stats_reset(port_id);

    Py_RETURN_NONE;
}

static PyObject *clear_port_xstats(PyObject* self, PyObject* args)
{
    uint16_t port_id;

    if (!PyArg_ParseTuple(args, "H", &port_id))
        return NULL;

    CHECK_PORT_ID(port_id);

    rte_eth_xstats_reset(port_id);

    Py_RETURN_NONE;
}

static PyObject *get_link(PyObject* self, PyObject* args)
{
    uint16_t port_id;
    struct rte_eth_link link;
    PyObject* res = NULL;

    if (!PyArg_ParseTuple(args, "H", &port_id))
        return NULL;

    CHECK_PORT_ID(port_id);

    memset(&link, 0, sizeof(link));
    rte_eth_link_get_nowait(port_id, &link);

    res = PyDict_New();

    PyDict_SetItemString(res, "speed", PyLong_FromUnsignedLong(link.link_speed));
    PyDict_SetItemString(res, "duplex", PyString_FromString((link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full") : ("half")));
    PyDict_SetItemString(res, "autoneg", (link.link_autoneg == ETH_LINK_AUTONEG) ? (Py_True) : (Py_False));
    PyDict_SetItemString(res, "status", (link.link_status == ETH_LINK_UP) ? (Py_True) : (Py_False));

    return res;
}

static PyObject *wait_linkup(PyObject* self, PyObject* args)
{
    uint16_t port_id;
    uint32_t index;
    struct rte_eth_link link;
    PyObject* res = NULL;

    if (!PyArg_ParseTuple(args, "H", &port_id))
        return NULL;

    CHECK_PORT_ID(port_id);

    memset(&link, 0, sizeof(link));

    for (index = 0; index < 10000; index++) {
        rte_eth_link_get_nowait(port_id, &link);

        if (link.link_status == ETH_LINK_UP) {
            break;
        }

        usleep(50000);
    }

    res = PyDict_New();

    PyDict_SetItemString(res, "speed", PyLong_FromUnsignedLong(link.link_speed));
    PyDict_SetItemString(res, "duplex", PyString_FromString((link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full") : ("half")));
    PyDict_SetItemString(res, "autoneg", (link.link_autoneg == ETH_LINK_AUTONEG) ? (Py_True) : (Py_False));
    PyDict_SetItemString(res, "status", (link.link_status == ETH_LINK_UP) ? (Py_True) : (Py_False));

    return res;
}

void cleanup()
{
#ifdef RTE_LIBRTE_PDUMP
    /* uninitialize packet capture framework */
    rte_pdump_uninit();
#endif
#ifdef RTE_LIBRTE_LATENCY_STATS
    rte_latencystats_uninit();
#endif

    force_quit();

    printf("Finished pytestpmd cleanup\\n");
}

static PyMethodDef pytestpmd_funcs[] = {
    { "get_valid_ports", (PyCFunction)get_valid_ports, METH_NOARGS, "get_valid_ports(): get list of valid port IDs\\n" },
    { "exec_cmd", (PyCFunction)exec_cmd, METH_VARARGS, "exec_cmd(cmd): execute testpmd string command\\n" },
    { "show_port_info", (PyCFunction)show_port_info, METH_VARARGS, "show_port_info(port_id): get basic info about port\\n" },
    { "show_port_stats", (PyCFunction)show_port_stats, METH_VARARGS, "show_port_stats(port_id): get basic statistics for port\\n" },
    { "show_port_xstats", (PyCFunction)show_port_xstats, METH_VARARGS, "show_port_xstats(port_id): get extended statistics for port\\n" },
    { "show_ports_info", (PyCFunction)show_ports_info, METH_VARARGS, "show_ports_info(): get information about all ports\\n" },
    { "clear_port_stats", (PyCFunction)clear_port_stats, METH_VARARGS, "clear_port_stats(port_id): clear basic statistics for port\\n" },
    { "clear_port_xstats", (PyCFunction)clear_port_xstats, METH_VARARGS, "clear_port_xstats(port_id): get extended statistics for port\\n" },
    { "get_link", (PyCFunction)get_link, METH_VARARGS, "get_link(port_id): get info about link on port\\n" },
    { "parse_args", (PyCFunction)parse_args, METH_VARARGS, "parse_args([list args]): set args to testpmd\\n" },
    { "wait_linkup", (PyCFunction)wait_linkup, METH_VARARGS, "wait_linkup(port_id): wait link up on port\\n" },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initlibpytestpmd(void)
{
    PyObject *module;

    int argc = 1;
    char *argv[] = { "pytestpmd" };

    int diag;
    portid_t port_id;
    int ret;

    // Init Python module
    module = Py_InitModule3("libpytestpmd", pytestpmd_funcs, "Python wrapper for testpmd functions");
    if (module == NULL)
        return;

    PyModule_AddStringConstant(module, "__version__", "0.0.1");
    DpdkError = PyErr_NewException("libpytestpmd.DpdkError", NULL, NULL);
    Py_INCREF(DpdkError);
    PyModule_AddObject(module, "DpdkError", DpdkError);
    Py_AtExit(cleanup);

    // Init testpmd
    rte_log_set_global_level(RTE_LOG_DEBUG);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    diag = rte_eal_init(argc, argv);
    if (diag < 0) {
        PyErr_SetString(DpdkError, "Cannot init EAL");
        return;
    }

    testpmd_logtype = rte_log_register("testpmd");
    if (testpmd_logtype < 0) {
        PyErr_SetString(DpdkError, "Cannot register log type");
        return;
    }
    rte_log_set_level(testpmd_logtype, RTE_LOG_DEBUG);

#ifdef RTE_LIBRTE_PDUMP
    /* initialize packet capture framework */
    rte_pdump_init(NULL);
#endif

    nb_ports = (portid_t) rte_eth_dev_count_avail();
    if (nb_ports == 0)
        TESTPMD_LOG(WARNING, "No probed ethernet devices\\n");

    /* allocate port structures, and init them */
    init_port();

    set_def_fwd_config();
    if (nb_lcores == 0) {
        PyErr_SetString(DpdkError, "Empty set of forwarding logical cores - check the core mask supplied in the command parameters");
        return;
    }

    /* Bitrate/latency stats disabled by default */
#ifdef RTE_LIBRTE_BITRATE
    bitrate_enabled = 0;
#endif
#ifdef RTE_LIBRTE_LATENCY_STATS
    latencystats_enabled = 0;
#endif

    /* on FreeBSD, mlockall() is disabled by default */
#ifdef RTE_EXEC_ENV_BSDAPP
    do_mlockall = 0;
#else
    do_mlockall = 1;
#endif

    if (do_mlockall) {
        TESTPMD_LOG(INFO, "Pre-loading and locking memory pages to increase performance\\n");
        if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
            TESTPMD_LOG(NOTICE, "mlockall() failed with error \\"%s\\"\\n", strerror(errno));
        }
    }

    if (tx_first && interactive) {
        PyErr_SetString(DpdkError, "--tx-first cannot be used on interactive mode");
        return;
    }

    if (tx_first && lsc_interrupt) {
        printf("Warning: lsc_interrupt needs to be off when using tx_first. Disabling.\\n");
        lsc_interrupt = 0;
    }

    if (!nb_rxq && !nb_txq)
        printf("Warning: Either rx or tx queues should be non-zero\\n");

    if (nb_rxq > 1 && nb_rxq > nb_txq)
        printf("Warning: nb_rxq=%d enables RSS configuration, but nb_txq=%d will prevent to fully test it.\\n", nb_rxq, nb_txq);

    init_config();

    if (hot_plug) {
        /* enable hot plug monitoring */
        ret = rte_dev_event_monitor_start();
        if (ret) {
            rte_errno = EINVAL;
            PyErr_SetString(DpdkError, "Failed to start hotplug monitor");
            return;
        }
        eth_dev_event_callback_register();
    }

    /* set all ports to promiscuous mode by default */
    RTE_ETH_FOREACH_DEV(port_id)
        rte_eth_promiscuous_enable(port_id);

    /* Init metrics library */
    rte_metrics_init(rte_socket_id());

#ifdef RTE_LIBRTE_LATENCY_STATS
    if (latencystats_enabled != 0) {
        int ret = rte_latencystats_init(1, NULL);
        if (ret)
            printf("Warning: latencystats init() returned error %d\\n",    ret);
        printf("Latencystats running on lcore %d\\n", latencystats_lcore_id);
    }
#endif

    /* Setup bitrate stats */
#ifdef RTE_LIBRTE_BITRATE
    if (bitrate_enabled != 0) {
        bitrate_data = rte_stats_bitrate_create();
        if (bitrate_data == NULL)
            rte_exit(EXIT_FAILURE, "Could not allocate bitrate data.\\n");
        rte_stats_bitrate_reg(bitrate_data);
    }
#endif
}
"""


def generate_pytestpmd(path):
    # pytestpmd.c
    with open(path, 'rt') as f:
        lines = f.readlines()

    lines.insert(0, '#include <eal_internal_cfg.h>\n')
    lines.insert(0, '#include <Python.h>\n')

    folder = os.path.dirname(os.path.abspath(path))
    new_path = os.path.join(folder, 'pytestpmd.c')

    text = ''.join(lines)
    text = text.replace('main(int argc, char** argv)', 'main_bak(int argc, char** argv)')

    with open(new_path, 'w') as f:
        f.write(text + patch)

    # meson.build
    files = ["app + '/{}'".format(f) for f in os.listdir(folder) if f[-2:] in ['.h', '.c'] and f[:-2] != 'testpmd']

    text = """
		if app == 'test-pmd'
			dep_objs += dependency('python2', required : true)
			py_sources = files({})
			shared_library('pytestpmd',
					py_sources,
					c_args: cflags,
					link_whole: link_libs,
					dependencies: dep_objs)
		endif"""
    text = text.format(',\n				'.join(files))

    path_to_meson = os.path.join(os.path.dirname(folder), 'meson.build')
    with open(path_to_meson, 'rt') as f:
        lines = f.readlines()

    for line in text.split('\n'):
        lines.insert(len(lines) - 2, line + '\n')

    with open(path_to_meson, 'w') as f:
        f.write(''.join(lines))
