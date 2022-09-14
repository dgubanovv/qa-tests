#include <unistd.h>
#include <memory.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
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

// Ring buffer for 3 frames
SCAN_LINE_T framebuffer[RES_Y*3];
int frame_n[3] = { 0, 1, 2 };

typedef struct pollfd t_poll_fd;

int main(int argc, char* argv[])
{
    int fd = udp_open(UDP_PORT);

    int i, f, n, n_fd = 0;
    t_poll_fd fds[2];

    do
    {
        fds[0].fd = fd;
        fds[n_fd].events = POLLIN|POLLPRI;
        fds[n_fd].revents = 0;
        n_fd = 1;

        // Check for events
        n = poll(fds, n_fd, POLL_TIMEOUT);
        if(n > 0)
        {
            SCAN_LINE_T rx_buff;
            struct sockaddr_in addr;
            socklen_t addrlen;

            addrlen = sizeof(addr);
            memset(&addr, 0, sizeof(addr));
            n = recvfrom(fd, &rx_buff, sizeof(rx_buff), 0, (struct sockaddr *)&addr, &addrlen);
            if(n < 0)
            {
                perror("recvfrom");
            }
            else
            {
                f = -1;
                if(frame_n[2] == rx_buff.frame) f = 2;
                else if(frame_n[1] == rx_buff.frame) f = 1;
                else if(frame_n[0] == rx_buff.frame) f = 0;
                else if(frame_n[2] < rx_buff.frame)
                {
                    // Check frame #0
                    int e = 0;
                    for(i = 0; i < RES_Y; ++i)
                    {
                        if(framebuffer[i + RES_Y*0].frame != frame_n[0] || framebuffer[i + RES_Y*0].line != i) ++e;
                    }
                    if(e) printf("Frame #%d: %d missed packets\n", frame_n[0], e);

                    printf("New frame: %d\n", rx_buff.frame);
                    frame_n[0] = frame_n[1]; memcpy(&framebuffer[RES_Y*0], &framebuffer[RES_Y*1], sizeof(SCAN_LINE_T)*RES_Y);
                    frame_n[1] = frame_n[2]; memcpy(&framebuffer[RES_Y*1], &framebuffer[RES_Y*2], sizeof(SCAN_LINE_T)*RES_Y);
                    frame_n[2] = rx_buff.frame;
                    f = 2;
                    for(i = 0; i < RES_Y; ++i)
                    {
                        framebuffer[i + RES_Y*f].frame = 0;
                        framebuffer[i + RES_Y*f].line = 0;
                    }

                }
                else
                {
                    printf("Missed frame data: %d\n", rx_buff.frame);
                }
                if(f >= 0)
                {
                    // printf("[%d] #%d: %d\n", f, rx_buff.frame, rx_buff.line);
                    memcpy(&framebuffer[rx_buff.line + RES_Y*f], &rx_buff, sizeof(rx_buff));
                }
            }
        }
    } while(1);

    close(fd);
    return 0;
}
