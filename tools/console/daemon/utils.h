/*\
 *  Copyright (C) International Business Machines  Corp., 2005
 *  Author(s): Anthony Liguori <aliguori@us.ibm.com>
 *
 *  Xen Console Daemon
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
\*/

#ifndef CONSOLED_UTILS_H
#define CONSOLED_UTILS_H

#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>

#include "xs.h"

void daemonize(const char *pidfile);
bool xen_setup(void);
#define read_sync(fd, buffer, size) _read_write_sync(fd, buffer, size, true)
#define write_sync(fd, buffer, size) _read_write_sync(fd, buffer, size, false)
bool _read_write_sync(int fd, void *data, size_t size, bool do_read);

extern int xcs_ctrl_fd;
extern int xcs_data_fd;
extern struct xs_handle *xs;
extern int xc;

#if 1
#define dolog(val, fmt, ...) syslog(val, fmt, ## __VA_ARGS__)
#else
#define dolog(val, fmt, ...) fprintf(stderr, fmt "\n", ## __VA_ARGS__)
#endif

#endif
