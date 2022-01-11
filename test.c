#include "nss-filter.c"
#include <stdio.h>

static void
test_match(const char *s)
{
  printf("%s: %s\n", s, filter_match_p(s) ? "match" : "-");
}

int main(int argc, char **argv)
{
  if (1 < argc)
    {
      int n;
      for(n=1; n<argc; ++n)
	test_match(argv[n]);
    }
  else
    {
      printf("NSS filter pattern test." "\n"
	     "Usage: %s host ..." "\n", argv[0]);
    }
  
  return 0;
}
