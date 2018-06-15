/*
* signal_tracker.h
*
* Keep track of a signal and report it if it has changed a lot
*
* Copyright (c) 2018, Afero Inc. All rights reserved.
*/

#ifndef __SIGNAL_TRACKER_H__
#define __SIGNAL_TRACKER_H__

/* This is a singleton class for now */

#define SIGTRACK_MAX_SIZE 16

/* clears the signal array, size must be less than SIGTRACK_MAX_SIZE */
void sigtrack_clear(int size);

/* returns signal if it should be reported or 0 otherwise
 * the absolute difference between the average and the signal
 * must be equal to or greater than diff_to_report for the
 * signal to be reported.
 */
int sigtrack_add(int signal, int diff_to_report);

#endif // __SIGNAL_TRACKER_H__


