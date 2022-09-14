#ifndef _udpac_h_
#define _udpac_h_

#define RES_X           400
#define RES_Y           240
#define FPS             60
#define BPP             3


typedef struct
{
    uint64_t    frame;
    uint16_t    line;

    char        pix[RES_X*BPP];
} SCAN_LINE_T;

#endif