/* SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2012-2018 ANSSI. All Rights Reserved.*/
/* Copyright 2012 SGDSN/ANSSI */
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

/* controls polling loop execution */
static int DO_EXIT;

/* controls if logging is enabled or not */
static int DO_LOG;


/* LEVEL 0 is always display, */
#define LOG(level, args...) do { if(level <= DO_LOG) { fprintf(stdout, args); } } while(0);

#define ERROR(args...) do { fprintf(stderr, args); } while(0);




/* Executing action for corresponding received event */
void execute_action(char *command,
                    char *line,
                    const int length) {
  char *object = NULL;
  char *action = NULL;
  char *info = NULL;
  unsigned int i;

  LOG(2, "Received: %s\n", line);

  /* "parsing" the received event line */
  object = line;
  i = 0;
  while((i < length) && (line[i] != ' ')) ++i;
  if(i < length) {
    line[i++] = '\0';
    if(i < length) {
      action = &(line[i]);
      while((i < length) && (line[i] != ' ')) ++i;      
      if(i < length) {
        line[i++] = '\0';
        info = &(line[i]);
      }
    }
  }

  if(command) {
    pid_t pid;
    
    if((pid = fork())) {
      /* perhaps we should timeout not to wait indefinitely for the child to exit */
      waitpid(pid, NULL, 0);
    } else {
      char * args[2];
      args[0] = command;
      args[1] = NULL;
      if(object) (void)setenv("OBJECT", object, 1);
      if(action) (void)setenv("ACTION", action, 1);
      if(info) (void)setenv("INFO", info, 1);
      LOG(1, "Exec '%s' with OBJECT='%s' ACTION='%s' INFO='%s'\n",
          command,
          object ? object : "",
          action ? action : "",
          info ? info : "");
      if(execv(args[0], args)) {
        ERROR("Failed to execute command '%s': %s\n", command, strerror(errno));
      }
      exit(1);
    }
  } else {
    LOG(1, "No command to execute\n");
  }
}





/* Creates the UNIX socket at path socket_path, binds it, listen and
   returns it. Returns < 0 in case of error. */
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







/* Triggers soft termination of polling loop but also the respawning
   loop */
void sighandler(int signum) {
  DO_EXIT = 1 + signum;
}




void event_loop(const int socket, char *command) {
  char *buf = NULL;
  int buf_allocsize;
  int buf_size;

  buf_size = 0;
  buf_allocsize = LINE_MAX_SIZE;
  if((buf = malloc(buf_allocsize * sizeof(char))) == NULL) {
    ERROR("Failed to allocate memory\n");
    return;
  }
  
  do {
    int nb_read = 0;
    
    if(buf_allocsize == buf_size) buf_size = 0;

    nb_read = read(socket, &(buf[buf_size]), (buf_allocsize - buf_size));

    if(nb_read <= 0) {
      LOG(1, "Read failed on socket !\n");
      goto loop_exception;
    }
    
    if(nb_read) {
      unsigned int start = 0;
      unsigned int i;
      for(i = 0; i < nb_read; ++i) {
        if(buf[buf_size + i] == '\n') {
          buf[buf_size + i] = '\0'; /* \n -> \0 */
          execute_action(command, &(buf[start]), (buf_size + i) - start - 1);
          start = buf_size + i + 1;
        }
      }
      buf_size += nb_read;
      
      if(start) {
        memmove(buf, &(buf[start]), (buf_allocsize - start));
        buf_size -= start;
      }

    }

  } while(!DO_EXIT);

 loop_exception:
  return;
}




int main(int argc, char **argv) {
  char c;
  const char *socket_path;
  char *command;

  signal(SIGINT, sighandler);
  signal(SIGQUIT, sighandler);
  signal(SIGTERM, sighandler);

  /* not logging anything by default */
  DO_LOG = 0;

  command = NULL;

  socket_path = NULL;

  while((c = getopt(argc, argv, "c:vs:")) != EOF) {
    switch(c) {
    case 'c':
      command = optarg;
      break;
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

  if(command == NULL) {
    ERROR("Missing command to execute (-c <command>)\n");
    return 4;
  }
    

  
  do {
    int socket;

    DO_EXIT = 0;
    
    if((socket = create_socket(socket_path)) < 0) {
      goto main_sleep_and_continue;
    }
    
    LOG(1, "Connected to '%s'\n", socket_path);

    event_loop(socket, command);

main_sleep_and_continue:
    if(!DO_EXIT) {
      sleep(1);
    } else if(socket_path) close(socket);

  } while(!DO_EXIT);

  LOG(2, "Exiting...\n");
  
  return 0;
}

