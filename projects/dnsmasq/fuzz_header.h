/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "dnsmasq.h"

extern void fuzz_blockdata_cleanup();

// Simple garbage collector
#define GB_SIZE 100

void *pointer_arr[GB_SIZE];
static int pointer_idx = 0;

// If the garbage collector is used then this must be called as first thing
// during a fuzz run.
void gb_init() {
  pointer_idx = 0;

   for (int i = 0; i < GB_SIZE; i++) {
     pointer_arr[i] = NULL;
   }
}

void gb_cleanup() {
    /* Free back-to-front: daemon is pointer_arr[0], and dnsmasq's free_real()
      reads daemon->log_malloc on every free, so daemon must be freed LAST. */
    for(int i = GB_SIZE - 1; i >= 0; i--) {
        if (pointer_arr[i] != NULL) {
          free(pointer_arr[i]);
        }
  }
}

char *get_len_null_terminated(const uint8_t **data, size_t *size, size_t to_get) {
  if (*size < to_get || (int)*size < 0) {
    return NULL;
  }

  char *new_s = malloc(to_get + 1);
  memcpy(new_s, *data, to_get);
  new_s[to_get] = '\0';

  *data = *data+to_get;
  *size -= to_get;
  return new_s;
}

char *get_null_terminated(const uint8_t **data, size_t *size) {
#define STR_SIZE 75
  return get_len_null_terminated(data, size, STR_SIZE);
}

char *gb_get_random_data(const uint8_t **data, size_t *size, size_t to_get) {
  if (*size < to_get || (int)*size < 0) {
    return NULL;
  }

  char *new_s = malloc(to_get);
  memcpy(new_s, *data, to_get);

  pointer_arr[pointer_idx++] = (void*)new_s;

  *data = *data + to_get;
  *size -= to_get;

  return new_s;
}

char *gb_get_null_terminated(const uint8_t **data, size_t *size) {

  char *nstr = get_null_terminated(data, size);
  if (nstr == NULL) {
    return NULL;
  }
  pointer_arr[pointer_idx++] = (void*)nstr;
  return nstr;
}

char *gb_get_len_null_terminated(const uint8_t **data, size_t *size, size_t to_get) {

  char *nstr = get_len_null_terminated(data, size, to_get);
  if (nstr != NULL) {
    pointer_arr[pointer_idx++] = (void*)nstr;
  }
  return nstr;
}

char *gb_alloc_data(size_t len) {
  char *ptr = calloc(1, len);
  pointer_arr[pointer_idx++] = (void*)ptr;

  return ptr;
}

short get_short(const uint8_t **data, size_t *size) {
  if (*size <= 0) return 0;
  short c = (short)(*data)[0];
  *data += 1;
  *size-=1;
  return c;
}

int get_int(const uint8_t **data, size_t *size) {
  if (*size <= 4) return 0;
  const uint8_t *ptr = *data;
  int val = *((int*)ptr);
  *data += 4;
  *size -= 4;
  return val;
}
// end simple garbage collector.

const uint8_t *syscall_data = NULL;
size_t syscall_size = 0;


int fuzz_ioctl(int fd, unsigned long request, void *arg) {
  int fd2 = fd;
  unsigned long request2 = request;
  void *arg_ptr = arg;

  // SIOCGSTAMP
  if (request == SIOCGSTAMP) {
    struct timeval *tv = (struct timeval*)arg_ptr;
    if (tv == NULL) {
      return 0;
    }

    char *rand_tv = gb_get_random_data(&syscall_data, &syscall_size, sizeof(struct timeval));
    if (rand_tv == NULL) {
      return -1;
    }

    memcpy(tv, rand_tv, sizeof(struct timeval));
    return 0;
  }

  if (request == SIOCGIFNAME) {
    //printf("We got a SIOCGIFNAME\n");
    struct ifreq *ifr = (struct ifreq*)arg_ptr;
    if (ifr == NULL) {
      return -1;
    }
    for (int i = 0; i < IF_NAMESIZE; i++) {
      if (syscall_size > 0 && syscall_data != NULL) {
        ifr->ifr_name[i] = (char)*syscall_data;
        syscall_data += 1;
        syscall_size -= 1;
      }
      else {
        ifr->ifr_name[i] = 'A';
      }
    }
    ifr->ifr_name[IF_NAMESIZE-1] = '\0';
    return 0;
    //return -1;
  }
  if (request == SIOCGIFFLAGS) {
    return 0;
  }
  if (request == SIOCGIFADDR) {
    return 0;
  }

  //
  int retval = ioctl(fd2, request2, arg_ptr);
  return retval;
}


// Sysytem call wrappers
static char v = 0;
ssize_t fuzz_recvmsg(int sockfd, struct msghdr *msg, int flags) {

  struct iovec *target = msg->msg_iov;

  //printf("recvmsg 1 \n");
  if (syscall_size > 1) {
    char r = *syscall_data;
    syscall_data += 1;
    syscall_size -= 1;

    if (r == 12) {
      //printf("recvmsg 2\n");
      return -1;
    }
  }

  int j = 0;
  if (msg->msg_control != NULL) {
    for (;j < CMSG_SPACE(sizeof(struct in_pktinfo)); j++)
    {
      if (syscall_size > 0 && syscall_data != NULL) {
        ((char*)msg->msg_control)[j] = *syscall_data;
        syscall_data += 1;
        syscall_size -= 1;
      }
      else {
        ((char*)msg->msg_control)[j] = 'A';
      }
    }
  }

  int i = 0;
  for (; i < target->iov_len; i++) {
    if (syscall_size > 0 && syscall_data != NULL) {
      ((char*)target->iov_base)[i] = *syscall_data;
      syscall_data += 1;
      syscall_size -= 1;
    }
    else {
      ((char*)target->iov_base)[i] = 'A';
    }
  }

  if (msg->msg_namelen > 0) {
    memset(msg->msg_name, 0, msg->msg_namelen);
  }

  return i;
}


// dnsmasq specific stuff
int init_daemon(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  int retval = 0;

#define CLEAN_IF_NULL(arg) if (arg == NULL) goto cleanup;

  // Initialize daemon
  daemon = (struct daemon*)gb_alloc_data(sizeof(struct daemon));
  CLEAN_IF_NULL(daemon)

  // daemon misc
  daemon->max_ttl = 3600;
  daemon->neg_ttl = 3600;
  daemon->local_ttl = 0;
  daemon->min_cache_ttl = 0;

  // daemon->namebuff.
  daemon->namebuff      = gb_alloc_data(MAXDNAMESTR+1);
  daemon->workspacename = gb_alloc_data(MAXDNAMESTR+1);
  //daemon->keynames      = gb_alloc_data(MAXDNAMESTR+1);
  //daemon->cnames        = gb_alloc_data(MAXDNAMESTR+1);
  CLEAN_IF_NULL(daemon->namebuff)
  CLEAN_IF_NULL(daemon->workspacename)
      //CLEAN_IF_NULL(daemon->keynames)
      //CLEAN_IF_NULL(daemon->cnames)

  // daemon->naptr
  daemon->naptr = NULL;

  // daemon->int_names
  daemon->int_names = NULL;

  // daemon->addrbuf
  char *adbuf = gb_alloc_data(200);
  CLEAN_IF_NULL(adbuf)
  daemon->addrbuff = adbuf;

  // daemon->auth_zones
  daemon->auth_zones = NULL;

  // deamon->mxnames
  daemon->mxnames = NULL;

  // daemon->txt
  daemon->txt = NULL;

  // daemon->rr
  daemon->rr = NULL;

  // daemon->relay4
  daemon->relay4 = NULL;

  // deamon->bridges
  daemon->bridges = NULL;

  // daemon->if_names
  daemon->if_names = NULL;

  // daemon->if_addrs
  daemon->if_addrs = NULL;

  // daemon->if_except
  daemon->if_except = NULL;

  // daemon->dhcp_except
  daemon->dhcp_except = NULL;

  // daemon->authinterface
  daemon->authinterface = NULL;


  // daemon->ptr
  daemon->ptr = NULL;

  // daemon->dhcp
  daemon->dhcp = NULL;


  // daemon->dhcp6
  daemon->dhcp6 = NULL;

  // daemon->doing_dhcp6
  daemon->doing_dhcp6 = 0;

  // daemon->dhcp_buffs
  char *dhcp_buff = gb_alloc_data(DHCP_BUFF_SZ);
  char *dhcp_buff2 = gb_alloc_data(DHCP_BUFF_SZ);
  char *dhcp_buff3 = gb_alloc_data(DHCP_BUFF_SZ);

  CLEAN_IF_NULL(dhcp_buff)
  CLEAN_IF_NULL(dhcp_buff2)
  CLEAN_IF_NULL(dhcp_buff3)

  daemon->dhcp_buff = dhcp_buff;
  daemon->dhcp_buff2 = dhcp_buff2;
  daemon->dhcp_buff3 = dhcp_buff3;



  // daemon->ignore_addr
  daemon->ignore_addr = NULL;

  // daemon->doctors
  daemon->doctors = NULL;

  retval = 0;
  goto ret;
cleanup:
  retval = -1;

ret:
  return retval;
}
