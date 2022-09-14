#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>

#define DBG(format, ...) fprintf(stderr, "[%s:%d] " format "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define UDP_BUFF_SIZE       2048
#define DEFAULT_UDP_PORT    1234

typedef struct sockaddr_storage t_sockaddr_in;


int ip6 = 0;
int port = DEFAULT_UDP_PORT;
t_sockaddr_in peer = {0};

int ka_len = 0;
char* ka_pat = NULL;
int ka_timeout = 0;

int wu_len = 0;
char* wu_pat = NULL;
int wu_timeout = 0;

const char* ip2str(t_sockaddr_in* addr)
{
   static char buff[INET6_ADDRSTRLEN+6] = "";
   struct sockaddr_in*  v4 = (struct sockaddr_in*)addr;
   struct sockaddr_in6* v6 = (struct sockaddr_in6*)addr;
   
   const char* res = NULL;
   
   if(ip6)
   {
       res = inet_ntop(AF_INET6, &(v6->sin6_addr), buff, sizeof(buff));
       if(res) sprintf(buff+strlen(res), ":%d", ntohs(v6->sin6_port));
   }
   else
   {
       res = inet_ntop(AF_INET, &(v4->sin_addr), buff, sizeof(buff));
       if(res) sprintf(buff+strlen(res), ":%d", ntohs(v4->sin_port));
   }

   return res;
}

short ip2port(t_sockaddr_in* addr)
{
   struct sockaddr_in*  v4 = (struct sockaddr_in*)addr;
   struct sockaddr_in6* v6 = (struct sockaddr_in6*)addr;
   short res = 0;
   
   if(ip6) res = v6->sin6_port;
   else res = v4->sin_port;

   return res;
}

int udp_open()
{
    t_sockaddr_in addr;
    u_int yes=1;
    int fd = -1;

    do
    {
        if((fd = socket(ip6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)) < 0)
        {
            perror("socket");
            break;
        }

        // allow multiple sockets to use the same PORT number
        if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
        {
            perror("Reusing ADDR failed");
            close(fd);
            fd = -1;
            break;
        }

        memset(&addr, 0, sizeof(addr));
        if(ip6)
        {
            struct sockaddr_in6* a = (struct sockaddr_in6*)&addr;
            a->sin6_family = AF_INET6;
            a->sin6_addr = in6addr_any;
            a->sin6_port = htons(port);
            a->sin6_scope_id = 0;
        }
        else
        {
            struct sockaddr_in* a = (struct sockaddr_in*)&addr;
            a->sin_family = AF_INET;
            a->sin_addr.s_addr = htonl(INADDR_ANY);
            a->sin_port = htons(port);
        }
        
        // bind to receive address
        if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            perror("bind");
            close(fd);
            fd = -1;
            break;
        }

        // Set to non-blocking mode
        int flags = fcntl(fd, F_GETFL);
        flags |= O_NONBLOCK;
        if(fcntl(fd, F_SETFL, flags) < 0)
        {
            perror("fcntl");
            close(fd);
            fd = -1;
            break;
        }

    } while(0);

    return fd;
}

char* file_read(char* name, int* len)
{
    int rc, size = 0;
    char *res = NULL, *b = NULL;
    FILE* f = fopen(name, "r");

    do
    {
        if(f == NULL)
        {
            perror("fopen");
            break;
        }

        rc = fseek(f, 0, SEEK_END);
        if(rc != 0)
        {
            perror("fseek(END)");
            break;
        }

        size = ftell(f);
        if(size == -1)
        {
            perror("ftell");
            break;
        }

        rc = fseek(f, 0, SEEK_SET);
        if(rc != 0)
        {
            perror("fseek(SET)");
            break;
        }

        b = malloc(size);
        rc = fread(b, 1, size, f);
        if(rc != size)
        {
            perror("incomplete fread");
            break;
        }

        if(len) *len = size;

        res = b;
        b = NULL;

    } while(0);

    if(b) free(b);
    if(f) fclose(f);

    return res;
}

// !!! Only ONE client allowed at a time !!!
/*
    -6 - use IPv6 (must be first parameter in command line)
    -c - client mode, server IP:PORT
    -k - keepalive binary pattern filename
    -w - wakeup binary pattern filename
    -m - keepalive timeout in seconds (default: off)
    -t - wakeup timeout in seconds (default: off)
    -p - listen on port (default: 1234)
*/
int main(int argc, char* argv[])
{
    char str[INET6_ADDRSTRLEN];
    int i = 1, udp = -1, client = 0;
    char *s, *p;

    memset(&peer, 0, sizeof(peer));

    while(i < argc)
    {
        p = argv[i++];
        if(*p++ == '-') switch(*p)
        {
            case '6':
            {
                ip6 = 1;
                break;
            }
            case 'c':
            {
                s = argv[i++];
                p = strrchr(s, ':');
                if(p) *p++ = 0;
                if(ip6)
                {
                    struct sockaddr_in6* a = (struct sockaddr_in6*)&peer;
                    a->sin6_family = AF_INET6;
                    inet_pton(AF_INET6, s, &(a->sin6_addr));
                    a->sin6_port = htons(p ? atoi(p) : DEFAULT_UDP_PORT);
                    a->sin6_scope_id = 0;
                }
                else
                {
                    struct sockaddr_in* a = (struct sockaddr_in*)&peer;
                    a->sin_family = AF_INET;
                    a->sin_addr.s_addr = inet_addr(s);
                    a->sin_port = htons(p ? atoi(p) : DEFAULT_UDP_PORT);
                }
                DBG("Server address: %s", ip2str(&peer));
                client = 1;
                break;
            }
            case 'k':
            {
                s = argv[i++];
                ka_pat = file_read(s, &ka_len);
                if(ka_pat == NULL) exit(1);
                DBG("Keepalive pattern length: %d", ka_len);
                break;
            }
            case 'w':
            {
                s = argv[i++];
                wu_pat = file_read(s, &wu_len);
                if(wu_pat == NULL) exit(1);
                DBG("Wakeup pattern length: %d", wu_len);
                break;
            }
            case 'm':
            {
                s = argv[i++];
                ka_timeout = atoi(s);
                DBG("keepalive timeout: %i", ka_timeout);
                break;
            }
            case 't':
            {
                s = argv[i++];
                wu_timeout = atoi(s);
                DBG("wakeup timeout: %i", wu_timeout);
                break;
            }
            case 'p':
            {
                s = argv[i++];
                port = atoi(s);
                DBG("listen on port: %i", port);
                break;
            }
        }
    }

    time_t ka_time = (ka_timeout) ? time(0) + ka_timeout : 0;
    time_t wake = (wu_timeout) ? time(0) + wu_timeout : 0;
    udp = udp_open();
    if(udp == -1) exit(1);

    do
    {
        t_sockaddr_in addr;
        int nbytes;
        socklen_t addrlen;
        char buff[UDP_BUFF_SIZE];

        if(client && wake && wake < time(0))
        {
            DBG("Wakeup timeout expired.");
            break;
        }

        if(!client && ka_time && ka_time < time(0))
        {
            DBG("Keepalive timeout expired!");
            ka_time = 0;
        }

        if(!client && wake && wake < time(0) && ip2port(&peer) == 0)
        {
            DBG("Wakeup timeout expired, but no any keepalive received.");
            break;
        }

        sleep(1);

        addrlen = sizeof(addr);
        memset(&addr, 0, sizeof(addr));
        nbytes = recvfrom(udp, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &addrlen);
        if(nbytes < 0)
        {
            if(errno != EAGAIN && errno != EWOULDBLOCK) perror("recvfrom");
        }
        else
        {
            if(nbytes == 0)
            {
                DBG("Socket unexpectedly closed.");
                break;
            }

            if(client && nbytes == wu_len && memcmp(buff, wu_pat, wu_len) == 0)
            {
                DBG("Valid wakeup message from: %s", ip2str(&addr));
                break;
            }
            else if(!client && nbytes == ka_len && memcmp(buff, ka_pat, ka_len) == 0)
            {
                DBG("Valid keepalive message from: %s", ip2str(&addr));
                if(ip2port(&peer) == 0) peer = addr;
                if(ka_timeout) ka_time = time(0) + ka_timeout;
            }
            else
            {
                DBG("Invalid message from: %s", ip2str(&addr));
            }
        }

        if(client && ka_time && ka_time < time(0))
        {
            DBG("Sending keepalive to: %s", ip2str(&peer));
            if(sendto(udp, ka_pat, ka_len, 0, (struct sockaddr*)&peer, sizeof(peer)) < 0)
            {
                perror("sendto");
                continue;
            }
            ka_time = time(0) + ka_timeout;
        }
        if(!client && wake && wake < time(0) && ip2port(&peer) != 0)
        {
            DBG("Sending wakeup to: %s", ip2str(&peer));
            if(sendto(udp, wu_pat, wu_len, 0, (struct sockaddr*)&peer, sizeof(peer)) < 0)
            {
                perror("sendto");
                wake = time(0) + 1; // Retry in 1 second
                continue;
            }
            break;
        }
    } while(1);

    close(udp);
    if(ka_pat) free(ka_pat);
    if(wu_pat) free(wu_pat);
    return 0;
}
