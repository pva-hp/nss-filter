#include "config.h"
#include <regex.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netdb.h>
#include <nss.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

/* #ifndef ETCDIR */
/* #define ETCDIR "/etc" */
/* #endif	/\* ETCDIR *\/ */

#define SYSTEM_BLACKLIST_FILE 	"/etc/" BLACKLIST_FILE


struct regexp1
{
  regex_t regex;
  struct regexp1 *next;
};


static struct regexp1 *
all_regexp = 0;


__attribute__((destructor))
static void
free_filters()
{
  struct regexp1 *x;
  for(x = all_regexp; x; x=x->next)
    {
      regfree(&x->regex);
    }  
}


static void
add_filter(char *out, unsigned line_no)
{
  regex_t regex;
  
  int err = regcomp(&regex, out, REG_EXTENDED);
  if (!err)
    {
      struct regexp1 *x = malloc(sizeof(*x));      
      x->regex = regex;
      x->next = all_regexp;
      all_regexp = x;
    }
  else
    {
      char text[500];
      regerror(err, &regex, text, sizeof(text));
      regfree(&regex);      
      warnx("%s:%d: %s: %s", SYSTEM_BLACKLIST_FILE, line_no,
	    "Can't compile regexp", text);
    }  
}


static void
read_filters_stream(FILE *io)
{
  unsigned line_no = 1;
  int c = fgetc(io);

  char out[MAX_REGEX_LENGTH + 1];

  while(EOF != c)
    {
      if (' ' <= c)
	{
	  unsigned pn, size;
	  for (pn = size = 0;
	       '#' != c && '\n' != c && EOF != c && pn < MAX_REGEX_LENGTH;
	       c = fgetc(io))
	    {
	      out[pn++] = c;
	      if (' ' < c) size = pn;
	    }

	  if (pn - 1 < MAX_REGEX_LENGTH)
	    {
	      out[pn] = 0;
	      add_filter(out, line_no);		  
	    }
	  else if (pn)
	    {
	      warnx("%s:%d: %s (%d)", SYSTEM_BLACKLIST_FILE, line_no,
		    "Too long regexp", pn);
	    }
	      
	  /* skip the rest line (may be comment) */
	  while ('\n' != c && EOF != c) { c = fgetc(io); }
	}
      else
	{
	  if ('\n' == c) ++line_no;
	  c = fgetc(io);
	}
    }
}


static void
read_filters_file(const char *path)
{
  FILE *io;
  if (NULL != (io = fopen(path, "r")))
    {
      read_filters_stream(io);
      fclose(io);        
    }
  else
    warn("Can't read %s", path);
}


/* static const char * */
/* conf_file_path() */
/* { */
/*   char *found; */

/*   readlink("/proc/self/exe", path1, sizeof(path1)); */
/*   found = strstr(path1, "/bin/"); */
/*   if (found) */
/*     { */
/*       strcat(found, "/etc/" SYSTEM_BLACKLIST_FILE); */
/*       return path1; */
/*     } */

/*   return SYSTEM_BLACKLIST_FILE; */
/* } */


__attribute__((constructor))
static void
load_filters()
{
  char path[256];
  /* user file */
  snprintf(path, sizeof(path), "%s/.config/%s", getenv("HOME"), BLACKLIST_FILE);  
  read_filters_file(path);
  /* system file */
  read_filters_file(SYSTEM_BLACKLIST_FILE);
}


static bool
filter_match_p(const char *str)
{
  struct regexp1 *x;
  for(x = all_regexp; x; x=x->next)
    {
      if (0 == regexec(&x->regex, str, 0, 0, 0))
	return true;
    }

  return false;
}


struct mem_layout
{
  void* list[2];
  union
  {
    struct in_addr in;
    struct in6_addr in6;
  } addr;
};


enum nss_status
_nss_filter_gethostbyname2_r(const char *name,
			     int af,
			     struct hostent *ret,
			     char *buf,
			     size_t buflen,
			     int *errnop,
			     int *h_errnop)
{
  static const struct in6_addr in6_init = IN6ADDR_LOOPBACK_INIT;
  if ((AF_INET == af || AF_INET6 == af) && filter_match_p(name))
    {
      struct mem_layout *mem;      
      if (buflen < sizeof(*mem))
	{
	  *h_errnop = *errnop = EAGAIN;
	  return NSS_STATUS_TRYAGAIN;
	}
      
      mem = (void*)buf;
      
      ret->h_addrtype = af;
      if (AF_INET == af)
	{
	  mem->addr.in.s_addr = htonl(INADDR_LOOPBACK);
	  ret->h_length = sizeof(mem->addr.in);
	}
      else
	{
	  memcpy(&mem->addr.in6, &in6_init, sizeof(mem->addr.in6));
	  ret->h_length = sizeof(mem->addr.in6);
	}

      warnx("%s %s", name, "is blocked.");
      
      mem->list[0] = &mem->addr;
      mem->list[1] = 0;      
      ret->h_addr_list = (char **)mem;
      ret->h_aliases = (char **)(1 + mem->list);
      ret->h_name = "localhost";
      *h_errnop = *errnop = 0;
      return NSS_STATUS_SUCCESS;
    }
  
  *h_errnop = *errnop = ENOENT;
  return NSS_STATUS_UNAVAIL;
}
