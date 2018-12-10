/* SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2012-2018 ANSSI. All Rights Reserved.*/
/* Copyright 2015 SGDSN/ANSSI */
/* Distributed under the terms of the GNU Lesser General Public License v2.1 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>



/* controls if logging is enabled or not */
static int DO_LOG;


/* LEVEL 0 is always display, */

#define LOG(level, args...) do { if(level <= DO_LOG) { fprintf(stderr, args); } } while(0);

#define ERROR(args...) do { fprintf(stderr, args); } while(0);



/* Creates the UNIX socket at path socket_path, connects to it, and
   returns it. Returns <= 0 in case of error. */
int create_socket(const char *socket_path) {
  int res;
  struct sockaddr_un addr;

  if((res = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    ERROR("Unable to create a socket: %s\n", strerror(errno));
    return -1;
  }

  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path));
  
  if(connect(res, (struct sockaddr *)&addr, sizeof(addr))) {
    LOG(1,"Unable to connect socket: %s: %s\n", socket_path, strerror(errno));
    return -3;
  }

  return res;
}





void list_smartcards(const int socket) {
  char *buf = NULL;
  int buf_allocsize;
  int buf_size;
  int nb_read = 0;

  buf_size = 0;
  buf_allocsize = LINE_MAX_SIZE;
  if((buf = malloc(buf_allocsize * sizeof(char))) == NULL) {
    ERROR("Failed to allocate memory\n");
    return;
  }
  
  do {
    
    if(buf_allocsize == buf_size) buf_size = 0;

    nb_read = read(socket, &(buf[buf_size]), (buf_allocsize - buf_size));

    if(nb_read > 0) {
      unsigned int start = 0;
      unsigned int i;
      for(i = 0; i < nb_read; ++i) {
        if(buf[buf_size + i] == '\n') {
          buf[buf_size + i] = '\0';
          fprintf(stdout, "%s\n", &(buf[start]));
          start = buf_size + i + 1;
        }
      }
      buf_size += nb_read;
      
      if(start) {
        memmove(buf, &(buf[start]), (buf_allocsize - start));
        buf_size -= start;
      }
    }

  } while(nb_read > 0);
  
  if(buf) {
    free(buf);
  }
  
  return;
}




int main(int argc, char **argv) {
  char c;
  const char *socket_path;
  int socket;

  /* not logging anything by default */
  DO_LOG = 0;

  socket_path = NULL;

  while((c = getopt(argc, argv, "vs:")) != EOF) {
    switch(c) {
    case 'v':
      ++DO_LOG;
      break;
    case 's':
      socket_path = optarg;
      break;
    case '?':
      return 1;
    }
  }

  if(optind < argc) {
    ERROR("Too many parameters\n");
    return 2;
  }

  if(socket_path == NULL) {
    ERROR("Missing socket path (-s <path>)\n");
    return 3;
  }
    
  if((socket = create_socket(socket_path)) < 0) {
    goto main_exit;
  }
    
  LOG(1, "Connected to '%s'\n", socket_path);

  list_smartcards(socket);
  
main_exit:

  if(socket_path) close(socket);

  LOG(2, "Exiting...\n");
  
  return 0;
}

