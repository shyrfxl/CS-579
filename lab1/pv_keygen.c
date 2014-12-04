#include "pv.h"

void
write_skfile (const char *skfname, void *raw_sk, size_t raw_sklen)
{
  int fdsk = 0;
  char *s = NULL;
  int status = 0;

  /* armor the raw symmetric key in raw_sk using armor64 */

  /* YOUR CODE HERE */

  /* now let's write the armored symmetric key to skfname */
  s = (char *)malloc(128);
  bzero(s,128);
  s = armor64(raw_sk,32);
  if ((fdsk = open (skfname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());
    free (s);

    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
    
    s = NULL;
    free(raw_sk);
    raw_sk = NULL;
    close (fdsk);
    exit (-1);
  }
  else {
    status = write (fdsk, s, strlen (s));
    status = write (fdsk, "\n", 1);
    }
    free (s);
    close (fdsk);
    /* do not scrub the key buffer under normal circumstances
       (it's up to the caller) */ 

    if (status == -1) {
      printf ("%s: trouble writing symmetric key to file %s\n", 
	      getprogname (), skfname);
      perror (getprogname ());
      
    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
      s = NULL;
      free(raw_sk);
      raw_sk = NULL;
      close(fdsk);
      exit (-1);
    }
 }


void 
usage (const char *pname)
{
  printf ("Personal Vault: Symmetric Key Generation\n");
  printf ("Usage: %s SK-FILE \n", pname);
  printf ("       Generates a new symmetric key, and writes it to\n");
  printf ("       SK-FILE.  Overwrites previous file content, if any.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  /* YOUR CODE HERE */
  my_progname = (char *)malloc (20*sizeof(char));
  char *buf_key = NULL,*d_key = NULL;
  buf_key = (char *)malloc(32*sizeof(char));
  d_key = (char *)malloc(256*sizeof(char));
  u_int64_t s64 = 0;
  if (argc != 2) {
    usage (argv[0]);
  }
  else {
    setprogname (argv[0]);

    /* first, let's create a new symmetric key */
    ri ();

    /* Note that since we'll need to do both AES-CBC-MAC and HMAC-SHA1,
       there are actuall *two* symmetric keys, which could, e.g., be 
       stored contiguosly in a buffer */

    /* YOUR CODE HERE */
    bzero (buf_key, sizeof(buf_key));
    bzero (d_key, sizeof(d_key));
    prng_seed(buf_key,32);
    prng_getbytes(buf_key, 32);
   /* printf ("%s,%lu\n",buf_key,sizeof(buf_key));*/
    /* now let's armor and dump to disk the symmetric key buffer */
    /* YOUR CODE HERE */
    int i;
    for ( i = 0; i < 4; i++)
    {
        s64 = prng_gethyper();
        puthyper ( d_key+i*8, s64);
    }
    write_skfile(argv[1],d_key,strlen(d_key));
    /* finally, let's scrub the buffer that held the random bits 
       by overwriting with a bunch of 0's */
    bzero (buf_key,sizeof(buf_key));
    free(buf_key);
    buf_key = NULL;
    bzero (d_key,sizeof(d_key));
    free(d_key);
    d_key = NULL;

  }

  return 0;
}

