/*
* signal_tracker.c
*
* Keep track of a signal and report it if it has changed a lot
*
* Copyright (c) 2018, Afero Inc. All rights reserved.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include "af_log.h"
#include "../include/signal_tracker.h"

//#define TEST_SIGNAL

typedef struct signal_tracker {
    int numReadings;
    int tail;
    int size;
    int readings[SIGTRACK_MAX_SIZE];
} signal_tracker_t;

static signal_tracker_t s_st;

void sigtrack_clear(int size)
{
    if (size < 0) {
        size = 1;
    } else if (size > SIGTRACK_MAX_SIZE) {
        size = SIGTRACK_MAX_SIZE;
    }
    s_st.size = size;
    s_st.numReadings = 0;
    s_st.tail = 0;
}

/* returns signal if it should be reported or 0 otherwise */
int sigtrack_add(int signal, int diff_to_respond)
{
    if (diff_to_respond < 0) {
        diff_to_respond = 0;
    }
    int ret = 0, avg = 0;

    /* find average */
    for (int i = 0; i < s_st.numReadings; i++) {
        avg += s_st.readings[i];
    };

    if (s_st.numReadings) {
        avg /= s_st.numReadings;

        /* determine if delta is outside of reporting range */
        int diff = signal - avg < 0 ? avg - signal: signal - avg;

        if (diff >= diff_to_respond) {
            ret = signal;
        }
#ifdef TEST_SIGNAL
        printf ("avg=%d signal=%d diff=%d\n", avg, signal, diff);
#endif
        AFLOG_DEBUG2("%s_info:avg=%d,signal=%d,diff=%d", __func__, avg, signal, diff);
    } else {
        /* always report the first signal */
        ret = signal;
    }

    /* insert the new signal in the list */
    s_st.readings[s_st.tail] = signal;

    /* increment tail with wraparound */
    s_st.tail = s_st.tail + 1;
    if (s_st.tail >= s_st.size) {
        s_st.tail = 0;
    }

    if (s_st.numReadings < s_st.size) {
        s_st.numReadings ++;
    }

    return ret;
}

#ifdef TEST_SIGNAL
void sigtrack_dump(void)
{
    if (s == NULL) {
        return;
    }
    printf("numReadings=%d tail=%d\nreadings: ", s_st.numReadings, s_st.tail);
    for (int i = 0; i < s_st.numReadings; i++) {
        printf(i == 0 ? "%d" : " %d", s_st.readings[i]);
    }
    printf("\n");
}

int main(int argc, char *arg[])
{
    sigtrack_clear(4);
    while(1) {
        char buf[128];
        fprintf(stdout, "enter a signal level: ");
        fgets(buf, sizeof(buf), stdin);
        if (buf[0] == 'q') {
            break;
        }
        int signal = atoi(buf);
        int ret = sigtrack_add(signal, 5);
        sigtrack_dump();
        printf("ret=%d\n",ret);
    }
    return 0;
}
#endif
