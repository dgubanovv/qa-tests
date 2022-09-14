#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

enum aq_sync_cntr_action {
	aq_sync_cntr_nop = 0, /* no action */
	aq_sync_cntr_set, /* set new counter value */
	aq_sync_cntr_add, /* add value to counter value */
	aq_sync_cntr_sub, /* subtract value from counter value */
};

struct aq_ptp_sync1588 {
	uint64_t time_ns;
	enum aq_sync_cntr_action action;
	uint16_t sync_pulse_ms;
	uint8_t clock_sync_en; /* Enabling sync clock */
} __attribute__((packed));

static void usage(const char *s)
{
	static const char *parameters_format = "     %-24s %s\n";
	printf("# usage: %s -i <ifname> [ -h | t]\n", s);
	printf(" Test PTP functions\n");
	printf(" Options:\n");
	printf(parameters_format, "-p <pulse ms>", "enable sync with external signal with period");
	printf(parameters_format, "-t <time>", "enable set new PTP time using sync1588 pin");
	printf(parameters_format, "-h", "display this help");
}

int aq_set_ptp_time(const char *ifname, struct aq_ptp_sync1588 *sync)
{
	int rc;
	int fd;
	struct sockaddr_in addr;
	struct ifreq ifr;
	char ipaddr[INET_ADDRSTRLEN];
	struct sockaddr_in *sa_in;

	fd = socket(PF_INET, SOCK_DGRAM, 0);

	if (fd == -1)
		err(1, "socket() failed");

	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_data = (char*)sync;

	if (ioctl(fd, SIOCDEVPRIVATE + 1, &ifr) == -1) {
		err(1, "ioctl() SIOCDEVPRIVATE failed");
	}

	return 0;
}

int main(int argc, char **argv)
{
	const char *ifname = NULL;
	unsigned long ifindex =0;
	uint64_t ptp_time = 0;
	uint16_t pulse_ms = 0;
	struct aq_ptp_sync1588 sync = {0};
	int err = 0;
	int ch;


	if (argc < 2) {
		usage(argv[0]);
		exit(0);
	}

	while ((ch = getopt(argc, argv, "hi:t:p:")) != -1) {
		switch (ch) {
		case 'i':
			ifname = optarg;
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				errx(1, "if_nametoindex(%s) failed", ifname);
				err = -1;
				break;
			}

			printf("ifindex = %lu\n", ifindex);
			break;
		case 't':
			if (sscanf(optarg, "%lu", &ptp_time) != 1) {
				errx(1, "invalid time value");
				err = -1;
			}
			break;
		case 'p':
			if (sscanf(optarg, "%hu", &pulse_ms) != 1) {
				errx(1, "invalid pulse value");
				err = -1;
			}
			break;
		case 'h':
		case '?':
		default:
			usage(argv[0]);
			exit(0);
			/* NOT REACHED */
		}
	}

	sync.time_ns = ptp_time;
	sync.action = (ptp_time ? aq_sync_cntr_set : aq_sync_cntr_nop);
	sync.clock_sync_en = (pulse_ms ? 1 : 0);
	sync.sync_pulse_ms = pulse_ms;

	if (!err)
		return aq_set_ptp_time(ifname, &sync);

	return 0;
}
