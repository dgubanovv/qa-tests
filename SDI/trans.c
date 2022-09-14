#include <unistd.h>
#include <memory.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DBG(format, ...) fprintf(stderr, "[%s:%d] " format "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#include "udpac.h"

// ----------------------------------------------------------------------------
#define POLL_TIMEOUT    1000
#define UDP_PORT        14381
#define UDP_GROUP       "225.0.0.7"
#define UDP_BUFF_SIZE   8*1024
// ----------------------------------------------------------------------------

int udp_open(int port)
{
    struct sockaddr_in addr;
    struct ip_mreq mreq;
    u_int yes=1;
    int fd = -1;

    do
    {
        /* create what looks like an ordinary UDP socket */
        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
            perror("socket");
            break;
        }

        /* allow multiple sockets to use the same PORT number */
        if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
        {
            perror("Reusing ADDR failed");
            break;
        }

        /* set up destination address */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        /* bind to receive address */
        if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("bind");
            close(fd);
            fd = -1;
            break;
        }

        /* use setsockopt() to request join a multicast group */
        mreq.imr_multiaddr.s_addr = inet_addr(UDP_GROUP);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        if(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
        {
            perror("setsockopt");
            close(fd);
            fd = -1;
            break;
        }
    } while(0);

    return fd;
}

void udp_send(int fd, uint8_t* data, size_t len)
{
    struct sockaddr_in addr;

    /* set up destination address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(UDP_GROUP);
    addr.sin_port = htons(UDP_PORT);

    if(sendto(fd, data, len, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("sendto");
    }
}

#define NS_IN_SEC 1000000000
static inline struct timespec timespec_add(const struct timespec * restrict a, time_t sec, long nsec)
{
    unsigned long nsecs = (a->tv_nsec % NS_IN_SEC) + (nsec % NS_IN_SEC);
    struct timespec result =
      { a->tv_sec + sec + (a->tv_nsec / NS_IN_SEC) + (nsec / NS_IN_SEC) + (nsecs / NS_IN_SEC), nsecs % NS_IN_SEC };
    return result;
}

SCAN_LINE_T framebuffer[RES_Y];

int main(int argc, char* argv[])
{
    int fd = udp_open(UDP_PORT);
    int i, f = 0;
    struct sockaddr_in addr;

    /* set up destination address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(UDP_GROUP);
    addr.sin_port = htons(UDP_PORT);

    for(i = 0; i < RES_Y; ++i)
    {
        framebuffer[i].frame = f;
        framebuffer[i].line = i;
    }

    long f_delay = NS_IN_SEC / FPS;
    long l_delay = f_delay / RES_Y;

    struct timespec ts, ts_f, ts_l;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    for(f = 0; f < 6000; ++f)
    {

        for(i = 0; i < RES_Y; ++i)
        {
            framebuffer[i].frame = f;
            ts_l = timespec_add(&ts, 0, l_delay*i);
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts_l, 0);
            if(sendto(fd, &framebuffer[i], sizeof(SCAN_LINE_T), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            {
                perror("sendto");
            }
        }
        ts_f = timespec_add(&ts, 0, f_delay);
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts_f, 0);
        ts = ts_f;
    }

    close(fd);
    return 0;
}
