/*SPDX-License-Identifier: LGPL-2.1-or-later
* Copyright © 2012-2018 ANSSI. All Rights Reserved.*/
/* Copyright 2012 SGDSN/ANSSI */
/* Distributed under the terms of the GNU Lesser General Public License v2.1 */

/* this is from PCSC library */
#include <winscard.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>


/* CLIP : vserver stuff */
#ifdef CLIP
#include <limits.h>
#include <sys/wait.h>
#include <clip/clip.h>
#include <linux/capability.h>
#include <clip/clip-vserver.h>

/* Context ID to be jailed in */
static int G_CONTEXT_ID = 0;
#endif



/* controls polling loop execution */
static int DO_EXIT;

/* controls respawning of poll loop in case pcscd is no more
   available */
static int DO_FOREVER;

/* controls if logging is enabled or not */
static int DO_LOG;

/* thread for the loop accepting clients on event notifier */
static pthread_t G_CLIENTS_THREAD;
/* mutex to control access to G_CLIENTS* data structures */
static pthread_mutex_t G_CLIENTS_MUTEX;
/* allocated size (i.e. item count) of the G_CLIENTS array */
static int G_CLIENTS_MAXSIZE;
/* number of clients connected (i.e. number of items in the G_CLIENTS array) */
static int G_CLIENTS_SIZE;
/* array of clients' fd */
static int *G_CLIENTS;

/* thread for the loop accepting clients on event lister */
static pthread_t G_LISTER_THREAD;
/* mutex to control access to G_LISTER* data structures */
static pthread_mutex_t G_LISTER_MUTEX;






/* LEVEL 0 is always display, */
#define LOG(level, args...) do { if(level <= DO_LOG) { fprintf(stdout, args); } } while(0);

#define ERROR(args...) do { fprintf(stderr, args); } while(0);


/* wrapper for PCSC library that does not mask correctly its error
   values */
#define PCSC_STRERROR(Val) pcsc_stringify_error(0xffffffff & (Val))


/* internal representation of a reader state */
typedef struct _reader_t {
  char *name; /* reader's name */
  unsigned int card_is_present;  /* 0 = no card, not 0 = contains a card */
  char card_atr[2*MAX_ATR_SIZE + 1];
  struct _reader_t *matcher; /* used internally to detect/match previously connected reader */
} reader_t;




static reader_t *G_LISTER_READERS;
static unsigned int G_LISTER_NB_READERS;





/* Returns 0 if OK, < 0 if no services, > 0 if another problem occured */
int get_readers(SCARDCONTEXT hContext,
                reader_t **readers,
                unsigned int *nbReaders) {
  unsigned int i;
  char *ptr;
  LONG ret;
  LPSTR pcscReaders = NULL;
  DWORD pcscNbReaders;
  
  *readers = NULL;
  *nbReaders = 0;

  /* Asking PCSC to retrieve complete list of connected readers, and
     to allocate the returned multi-string */
  pcscNbReaders = SCARD_AUTOALLOCATE;
  ret = SCardListReaders(hContext, NULL, (LPSTR)&pcscReaders, &pcscNbReaders);
  if((ret != SCARD_S_SUCCESS) && (ret != SCARD_E_NO_READERS_AVAILABLE)) {
    LOG(1, "PCSC error: %s\n", PCSC_STRERROR(ret));
    return (ret == SCARD_E_NO_SERVICE) ? -1 : 1;
  }
  
  /* to fix the stupid implementation that do not set to the number of
     readers but to the length of the string returned... */
  if(ret == SCARD_E_NO_READERS_AVAILABLE)
    return 0;
  
  /* parsing multi-string list of connected readers names */
  if(pcscNbReaders > 0)
    for(i = 0; i < (pcscNbReaders - 1); ++i)
      if(pcscReaders[i] == '\0') ++(*nbReaders);
  
  /* allocating internal structures corresponding to the list of connected readers */
  if(*nbReaders) {
    *readers = malloc(sizeof(reader_t) * *nbReaders);
    if(*readers == NULL) {
      LOG(1,"Failed to allocate memory\n");
      SCardFreeMemory(hContext, pcscReaders);
      return 2;
    }
  
    ptr = pcscReaders;
    for(i = 0; i < *nbReaders; ++i) {
      (*readers)[i].name = strdup(ptr);
      (*readers)[i].card_is_present = 0; /* at reader insertion we
                                            assume no card is present,
                                            this will be updated
                                            later, */
      (*readers)[i].card_atr[0] = '\0';
      (*readers)[i].matcher = NULL;
      ptr += strlen(ptr) + 1;
    }
  }
  
  SCardFreeMemory(hContext, pcscReaders);

  return 0;
}


/* Broadcast the received event (add/remove) on reader related to
   object (card/reader) to connected clients. Removes
   unreachable/disconnected clients on the fly. */
void notify_clients(const char *object,
                    const char *event,
                    const unsigned char dump_atr,
                    const reader_t *reader) {
  unsigned int i;
  char line[LINE_MAX_SIZE];
  int line_size;

  /* event line as it will be sent to clients */
  if(dump_atr) {
    LOG(1, "%s %s card_atr '%s'\n", object, event, reader->card_atr);
    line_size = snprintf(line, LINE_MAX_SIZE, "%s %s %s", object, event, reader->card_atr);
  } else {
    LOG(1, "%s %s reader '%s'\n", object, event, reader->name);
    line_size = snprintf(line, LINE_MAX_SIZE, "%s %s %s", object, event, reader->name);
  }
  line[line_size-1] = '\n'; /* we ensure the line is CR terminated,
                               possibly truncating the reader
                               name if LINE_MAX_SIZE is too short */

  /* locking access to G_CLIENTS* data structures */
  pthread_mutex_lock(&G_CLIENTS_MUTEX);
  
  i = 0;
  while(i < G_CLIENTS_SIZE) {
    if(write(G_CLIENTS[i], line, line_size) < line_size) {

      LOG(2, "Client %i has left\n", G_CLIENTS[i]);

      --G_CLIENTS_SIZE;

      if(i < G_CLIENTS_SIZE)
        G_CLIENTS[i] = G_CLIENTS[G_CLIENTS_SIZE];

    } else ++i;
  }

  pthread_mutex_unlock(&G_CLIENTS_MUTEX);
  /* unlocked access to G_CLIENTS* data structures*/

}


/* Event wrapper when a card is inserted */
void inserted_card_event(reader_t *reader,
                         const unsigned char atr[MAX_ATR_SIZE],
                         const unsigned int atr_size) {
  unsigned int i, size;
  size = atr_size;
  if(size > MAX_ATR_SIZE) size = MAX_ATR_SIZE;
  for(i = 0; i < size; ++i) {
    snprintf(&(reader->card_atr[2*i]), 2+1, "%.2X", atr[i]);
  }
  reader->card_atr[2*size] = '\0';
  reader->card_is_present = 1;

  notify_clients("card", "add", 1, reader);
}

/* Event wrapper when a card is removed */
void removed_card_event(reader_t *reader) {
  notify_clients("card", "remove", 1, reader);
  reader->card_is_present = 0;
  reader->card_atr[0] = '\0';
}

/* Event wrapper when a reader is connected */
void connected_reader_event(reader_t *reader) {
  notify_clients("reader", "add", 0, reader);
}

/* Event wrapper when a reader is disconnected */
void removed_reader_event(reader_t *reader) {

  /* automatically dealing with card removal if a card was present before
     reader's removal */
  if(reader->card_is_present)
    removed_card_event(reader);

  notify_clients("reader", "remove", 0, reader);
}

/* Updates the state (card present or not) of given readers, and
   triggers corresponding card related actions. Returns 0 if OK, < 0 if no services, > 0 if another problem occured */
int update_readers_state(SCARDCONTEXT hContext,
                         reader_t *readers,
                         unsigned int nbReaders) {

  SCARD_READERSTATE *states = NULL;
  LONG ret;
  unsigned int i;

  if(nbReaders == 0) return 0;
  
  states = malloc(sizeof(SCARD_READERSTATE) * nbReaders);
  for(i = 0; i < nbReaders; ++i) {
    states[i].szReader = readers[i].name;
    states[i].dwCurrentState = SCARD_STATE_UNAWARE;
  }
  
  /* Asking for reader state (it returns immediately so timeout is useless */
  ret = SCardGetStatusChange(hContext, INFINITE, states, nbReaders);
  if(ret != SCARD_S_SUCCESS) {
    LOG(1, "PCSC error: %s\n", PCSC_STRERROR(ret));
    free(states);
    return (ret == SCARD_E_NO_SERVICE) ? -1 : 1;
  }
        
  for(i = 0; i < nbReaders; ++i) {
    if(states[i].dwEventState & SCARD_STATE_PRESENT) {
      if(!(readers[i].card_is_present))
        inserted_card_event(&(readers[i]), states[i].rgbAtr, states[i].cbAtr);
    } else if(states[i].dwEventState & SCARD_STATE_EMPTY) {
      if(readers[i].card_is_present)
        removed_card_event(&(readers[i]));
    }
  }

  free(states);

  return 0;
}



/* Fills the matcher field of internal reader's state structures to
   detect/match previously connected readers. */
void match_readers(reader_t *prevReaders,
                   unsigned int prevNbReaders,
                   reader_t *readers,
                   unsigned int nbReaders) {
  unsigned int i, j;
  
  for(i = 0; i < nbReaders; ++i)
    readers[i].matcher = NULL;

  for(j = 0; j < prevNbReaders; ++j)
    prevReaders[j].matcher = NULL;
  
  /* matching readers, naively */
  for(i = 0; i < nbReaders; ++i) {
    j = 0;
    while((j < prevNbReaders) && (readers[i].matcher == NULL)) {
        if((prevReaders[j].matcher == NULL)
           && (strcmp(readers[i].name, prevReaders[j].name) == 0)) {
          readers[i].matcher = &(prevReaders[j]);
          prevReaders[j].matcher = &(readers[i]);
          readers[i].card_is_present = prevReaders[j].card_is_present;
          strncpy(readers[i].card_atr, prevReaders[j].card_atr, 2*MAX_ATR_SIZE+1);
        }
        ++j;
    }
  }
  for(j = 0; j < prevNbReaders; ++j) {
    i = 0;
    while((i < nbReaders) && (prevReaders[j].matcher == NULL)) {
      if((readers[i].matcher == NULL) && (strcmp(readers[i].name, prevReaders[j].name) == 0)) {
        readers[i].matcher = &(prevReaders[j]);
        prevReaders[j].matcher = &(readers[i]);
        readers[i].card_is_present = prevReaders[j].card_is_present;
      }
      ++i;
    }
  }

}



/* If pcscd is running, continously polls it to detect reader/card
   insertions/removals. Exits if pcscd is no more available, or if
   PCSC library context is no more valid according to PCSC. */
void poll_loop(SCARDCONTEXT hContext) {
  
  int i;
  

  do {
    reader_t *readers = NULL;
    unsigned int nbReaders = 0;
    
    if(SCardIsValidContext(hContext) != SCARD_S_SUCCESS) {
      ERROR("PCSC daemon is no more available\n");
      return;
    }

    pthread_mutex_lock(&G_LISTER_MUTEX);

    if((i = get_readers(hContext, &readers, &nbReaders))) {
      LOG(1, "Failed to retrieve readers list\n");
      /* if i < 0, then it means PCSC is no more available, so exits
         the polling loop is mandatory. */
      if(i < 0) DO_EXIT = 1;
      goto sleep_and_continue;
    }

    match_readers(G_LISTER_READERS, G_LISTER_NB_READERS,
                  readers, nbReaders);
    
    /* we enumerate removed readers */
    for(i = 0; i < G_LISTER_NB_READERS; ++i)
      if(G_LISTER_READERS[i].matcher == NULL)
        removed_reader_event(&(G_LISTER_READERS[i]));

    /* we enumerate added readers */
    for(i = 0; i < nbReaders; ++i)
      if(readers[i].matcher == NULL)
        connected_reader_event(&(readers[i]));

    if((i = update_readers_state(hContext, readers, nbReaders))) {
      LOG(1, "Failed to update readers state\n");
      /* if i < 0, then it means PCSC is no more available, so exits
         the polling loop is mandatory. */
      if(i < 0) DO_EXIT = 1;
      for(i = 0; i < nbReaders; ++i)
        free(readers[i].name);
      free(readers);
      goto sleep_and_continue;
    }


    /* freeing previous structures */
    if(G_LISTER_READERS) {
      for(i = 0; i < G_LISTER_NB_READERS; ++i) {
        free(G_LISTER_READERS[i].name);          
      }
      free(G_LISTER_READERS);
    }
    
    /* saving current structures */

    G_LISTER_READERS = readers;
    G_LISTER_NB_READERS = nbReaders;

  sleep_and_continue:

    pthread_mutex_unlock(&G_LISTER_MUTEX);

    sleep(1);
    
  } while(!DO_EXIT);


  pthread_mutex_lock(&G_LISTER_MUTEX);

  /* freeing previous structures */
  if(G_LISTER_READERS) {
    for(i = 0; i < G_LISTER_NB_READERS; ++i) {
      free(G_LISTER_READERS[i].name);          
    }
    free(G_LISTER_READERS);
  }

  pthread_mutex_unlock(&G_LISTER_MUTEX);

  LOG(2, "Exiting the polling loop\n");
}




/* Creates the UNIX socket at path socket_path, binds it, listen and
   returns it. Returns < 0 in case of error. */
int create_socket(const char *socket_path) {
  int res;
  struct sockaddr_un addr;
  mode_t prev;

  if((res = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    ERROR("Unable to create a socket: %s\n", strerror(errno));
    return -1;
  }

  addr.sun_family = AF_UNIX;
  unlink(socket_path);
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path));
  
  prev = umask(S_IXUSR | S_IXGRP | S_IXOTH); 
  if(bind(res, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    ERROR("Unable to bind to socket: %s: %s\n", socket_path, strerror(errno));
    prev = umask(prev);
    return -2;
  }
  
  if(listen(res, 42) < 0) {
    ERROR("Unable to listen on socket: %s: %s\n", socket_path, strerror(errno));
    prev = umask(prev);
    return -3;
  }

  if((fchmod(res, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) < 0) {
    ERROR("Unable to fchmod socket: %s: %s\n", socket_path, strerror(errno));
    prev = umask(prev);
    return -4;
  }
  prev = umask(prev);

  return res;
}


/* Method responsible of accepting clients on the notification socket
   and of updating the G_CLIENTS* data structures accordingly. */
void *accept_notifier_clients(void *arg) {
  int socket = *(int*)arg;
  struct sockaddr addr_cli;
  socklen_t addr_cli_size;
  int addr_cli_fd;
  

  while(!DO_EXIT) {

    if((addr_cli_fd = accept(socket, &addr_cli, &addr_cli_size)) < 0) {
      ERROR("Failed to accept client: %s\n", strerror(errno));
    } else {
      
      /* locking access to G_CLIENTS* data structures */
      if(pthread_mutex_lock(&G_CLIENTS_MUTEX)) {
        ERROR("Failed to lock mutex\n");
        pthread_exit(NULL);
      }
      
      if(G_CLIENTS_SIZE >= G_CLIENTS_MAXSIZE) {
        G_CLIENTS_MAXSIZE += 10;
        if((G_CLIENTS = realloc(G_CLIENTS, G_CLIENTS_MAXSIZE * sizeof(int))) == NULL) {
          ERROR("Failed to realloc clients array\n");
          G_CLIENTS_SIZE = 0;
          G_CLIENTS_MAXSIZE = 0;
          pthread_mutex_unlock(&G_CLIENTS_MUTEX); /* not to block others waiting */
          pthread_exit(NULL);
        }
      }

      LOG(2, "Client notifier %i is now connected\n", addr_cli_fd);

      G_CLIENTS[G_CLIENTS_SIZE++] = addr_cli_fd;
      
      /* unlocking access to G_CLIENTS* data structures */
      if(pthread_mutex_unlock(&G_CLIENTS_MUTEX)) {
        ERROR("Failed to unlock mutex\n");
        G_CLIENTS_SIZE = 0;
        G_CLIENTS_MAXSIZE = 0;
        pthread_exit(NULL);
      }

    }
  }
  
  return NULL;
}




/* Method responsible of accepting listing clients on the notification socket
   and of updating the G_CLIENTS* data structures accordingly. */
void *accept_lister_clients(void *arg) {
  int socket = *(int*)arg;
  struct sockaddr addr_cli;
  socklen_t addr_cli_size;
  int addr_cli_fd;

  while(!DO_EXIT) {

    if((addr_cli_fd = accept(socket, &addr_cli, &addr_cli_size)) < 0) {
      ERROR("Failed to accept client: %s\n", strerror(errno));
    } else {
      
      LOG(2, "Client lister %i is now connected\n", addr_cli_fd);

      pthread_mutex_lock(&G_LISTER_MUTEX);
      
      /* freeing previous structures */
      if(G_LISTER_READERS) {
        char line[LINE_MAX_SIZE];
        int i, line_size;
        
        for(i = 0; i < G_LISTER_NB_READERS; ++i) {
          if(G_LISTER_READERS[i].card_is_present) {
            line_size = snprintf(line, LINE_MAX_SIZE, "%s %s\n", G_LISTER_READERS[i].name, G_LISTER_READERS[i].card_atr);
            line[line_size-1] = '\n';
            write(addr_cli_fd, line, line_size);
          }
        }
      }
      
      pthread_mutex_unlock(&G_LISTER_MUTEX);
      
      close(addr_cli_fd);

      LOG(2, "Client lister %i is now disconnected\n", addr_cli_fd);
    }
  }
  
  return NULL;
}



#ifdef CLIP 
int drop_privs(void) {
  if(G_CONTEXT_ID) {
    if(clip_enter_context(G_CONTEXT_ID)) {
      LOG(2, "Failed to enter context %u\n", G_CONTEXT_ID);
      return -1;
    }
    LOG(2, "Entered in context %u", G_CONTEXT_ID);
  }
  
  return 0;
}
#endif



/* Triggers soft termination of polling loop but also the respawning
   loop */
void sighandler(int signum) {
  DO_EXIT = 1 + signum;
  DO_FOREVER = 0;
  pthread_cancel(G_CLIENTS_THREAD); /* this is a bit rough... */
  pthread_cancel(G_LISTER_THREAD); /* this is a bit rough... */
}




void usage() {
  LOG(0, "Usage:\n");
  LOG(0, "  -d         Poll PCSC if it is not running\n");
  LOG(0, "  -h         This help\n");
  LOG(0, "  -v         Increase verbosity (-v -v ...)\n");
  LOG(0, "  -s <path>  Socket path\n");
#ifdef CLIP
  LOG(0, "  -X <ctx>   VServer context\n");
#endif
}




int main(int argc, char **argv) {
  char c;
  LONG ret;
  SCARDCONTEXT hContext;
  const char *notifier_socket_path;
  int notifier_socket;
  pthread_attr_t notifier_attr;
  pthread_mutexattr_t notifier_mutexattr;
  const char *lister_socket_path;
  int lister_socket;
  pthread_attr_t lister_attr;
  pthread_mutexattr_t lister_mutexattr;
  
  signal(SIGINT, sighandler);
  signal(SIGQUIT, sighandler);
  signal(SIGTERM, sighandler);

  /* we properly handle SIGPIPE */
  signal(SIGPIPE, SIG_IGN);

  


  /* not logging anything by default */
  DO_LOG = 0;

  /* not respawning the polling loop by default */
  DO_FOREVER = 0;

  notifier_socket_path = NULL;
  notifier_socket = -1;
  lister_socket_path = NULL;
  lister_socket = -1;

  while((c = getopt(argc, argv, "dhl:s:vX:")) != EOF) {
    switch(c) {
    case 'd':
      DO_FOREVER = 1;
      break;
    case 'v':
      ++DO_LOG;
      break;
    case 'h':
      usage();
      return 0;
    case 's':
      notifier_socket_path = optarg;
      break;
    case 'l':
      lister_socket_path = optarg;
      break;
    case 'X':
#ifdef CLIP
      G_CONTEXT_ID = atoi(optarg);
      break;
#else
      ERROR("Invalid option (you should compile with CLIP defined if you want it...)\n");
#endif
    case '?':
      return 1;
    }
  }

  if(optind < argc) {
    ERROR("Too many parameters\n");
    usage();
    return 2;
  }


  if(notifier_socket_path) {
    if((notifier_socket = create_socket(notifier_socket_path)) < 0)
      return 3;
  } else {
    ERROR("Missing notifier socket_path !\n");
    usage();
    return 4;
  }

  LOG(1, "Accepting notifier clients on '%s'\n", notifier_socket_path);

  if(lister_socket_path) {
    if((lister_socket = create_socket(lister_socket_path)) < 0)
      return 3;
  } else {
    ERROR("Missing lister socket_path !\n");
    usage();
    return 5;
  }

  LOG(1, "Accepting lister clients on '%s'\n", lister_socket_path);

#ifdef CLIP
  if(drop_privs()) goto main_exit;
#endif

  if(pthread_attr_init(&notifier_attr)) {
    ERROR("Failed to create phtread attr\n");
    goto main_exit;
  }
  
  if(pthread_mutexattr_init(&notifier_mutexattr)) {
    ERROR("Failed to create mutex attr\n");
    goto main_exit;
  }
  
  if(pthread_mutex_init(&G_CLIENTS_MUTEX, &notifier_mutexattr)) {
    ERROR("Failed to create mutex\n");
    goto main_exit;
  }
  
  G_CLIENTS_SIZE = 0;
  G_CLIENTS_MAXSIZE = 10;
  if((G_CLIENTS = malloc(G_CLIENTS_MAXSIZE * sizeof(int))) == NULL) {
    ERROR("Failed to allocate client array\n");
    goto main_exit;
  }
  

  if(pthread_create(&G_CLIENTS_THREAD, &notifier_attr, accept_notifier_clients, (void*)&notifier_socket)) {
    ERROR("Failed to create phtread\n");
    goto main_exit;    
  }


  if(pthread_attr_init(&lister_attr)) {
    ERROR("Failed to create phtread attr\n");
    goto main_exit;
  }

  if(pthread_mutexattr_init(&lister_mutexattr)) {
    ERROR("Failed to create mutex attr\n");
    goto main_exit;
  }
  if(pthread_mutexattr_setpshared(&lister_mutexattr, PTHREAD_PROCESS_SHARED)) {
    ERROR("Failed to set pshared mutexattr\n");
    goto main_exit;
  }
  
  if(pthread_mutex_init(&G_LISTER_MUTEX, &lister_mutexattr)) {
    ERROR("Failed to create mutex\n");
    goto main_exit;
  }
  
  if(pthread_create(&G_LISTER_THREAD, &lister_attr, accept_lister_clients, (void*)&lister_socket)) {
    ERROR("Failed to create phtread\n");
    goto main_exit;
  }



  do {
    
    /* PCSC context creation for this application */
    ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if(ret != SCARD_S_SUCCESS) {
      ERROR("PCSC error: %s\n", PCSC_STRERROR(ret));
      goto main_sleep_and_continue;
    }

    DO_EXIT = 0;
    poll_loop(hContext);
    
    /* PCSC context release for this application */
    ret = SCardReleaseContext(hContext);
    if(ret != SCARD_S_SUCCESS) {
      LOG(1, "PCSC error: %s\n", PCSC_STRERROR(ret));
    }

  main_sleep_and_continue:
    if(DO_FOREVER) sleep(1);

  } while(DO_FOREVER);


  pthread_cancel(G_CLIENTS_THREAD); /* this is a bit rough... */
  pthread_mutexattr_destroy(&notifier_mutexattr);
  pthread_attr_destroy(&notifier_attr);
  
  pthread_cancel(G_LISTER_THREAD); /* this is a bit rough... */
  pthread_mutexattr_destroy(&lister_mutexattr);
  pthread_attr_destroy(&lister_attr);

  
 main_exit:

  if(notifier_socket_path) {
    int i;

    LOG(2, "Closing and unlinking accepting notifier socket '%s'\n", notifier_socket_path);
    close(notifier_socket);
    unlink(notifier_socket_path);

    for(i = 0; i < G_CLIENTS_SIZE; ++i) {
      LOG(2, "Closing connection with client %i\n", G_CLIENTS[i]);
      close(G_CLIENTS[i]);
    }
  }

  if(lister_socket_path) {
    LOG(2, "Closing and unlinking accepting lister socket '%s'\n", lister_socket_path);
    close(lister_socket);
    unlink(lister_socket_path);
  }
  
  return 0;
}

