#include "pv.h"

void
decrypt_file (const char *ptxt_fname, void *raw_sk, size_t raw_len, int fin)
{
   size_t size_pt = 0, number = 0;
   char *cdata = NULL, *data = NULL, *hdata = NULL, *mac_hdata = NULL;
   int status = 0;
   int fddt = 0;
   aes_ctx *aes = NULL;
   sha1_ctx *sc = NULL;
   if((fddt = open (ptxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600))== -1)
	{
		perror(getprogname ());
		return;
	}
    size_pt = 512;
    size_t tot;
    ssize_t cur;
    cdata = (char *)malloc (size_pt * sizeof(char));
    tot = 0;
    do 
    {
	cur = read (fin, cdata + tot, size_pt - tot);
	tot += cur;
	if (size_pt == tot)
	{
		size_pt <<=1;
		cdata = (char *)realloc (cdata, size_pt);
	}
    }while (cur > 0);
    if (cur == -1)
    {
	printf ("%s: trouble importing cipher text from file \n",getprogname());
	perror (getprogname ());
        free (cdata);
	close (fin);
	exit (-1);
    }
    else
    {
  	assert (cur == 0);
	cdata[tot] = '\0';		
    }
    char * ddata = (char *)malloc(size_pt*sizeof(char));
    size_pt = dearmor64(ddata,cdata);
    number = (size_pt - 22) /16;
    /*printf ("%lu,%lu\n",number,size_pt-22);*/
    data = (char *)malloc((size_pt)*sizeof(char));
    bzero(data, size_pt);
    hdata = (char *)malloc((20)*sizeof(char));
    aes = (aes_ctx *)malloc((16)*sizeof(aes_ctx));
    sc = (sha1_ctx *)malloc(20*sizeof(sha1_ctx));
    mac_hdata = (char *)malloc((100)*sizeof(char));
    bzero( mac_hdata, 20);
    size_t i = 0, j = 0;
	for( i = size_pt-22; i < size_pt-2; i++)
	{      
		hdata[j++] = ddata[i];

	}
	hmac_sha1_init ( raw_sk+16, 16, sc);
	/*printf("%s\n",mac_hdata);*/
	for ( i = 0; i<number; i++)
	{	
		hmac_sha1_update( sc,ddata+i*16,16);
	}
	hmac_sha1_final ( raw_sk+16, 16, sc, (u_char *)mac_hdata);
	for ( i = 0; i < 20; i++)
	{
		if( hdata[i]!=mac_hdata[i])
		{
			printf("%s: someting is changed in %s",getprogname(), ptxt_fname);
			close(fin);
			return;
		}
	}
	int kkk = 0;
	for (kkk = number-1; kkk>= 0; kkk--)
	{ 
		if ( kkk == 0)
		{
			aes_setkey (aes, raw_sk, 16);
		}
		else
		{
			aes_setkey (aes, ddata+(kkk-1)*16, 16);
		}
		aes_decrypt ( aes, data+kkk*16, ddata+kkk*16);
		/*printf("%d:%s\n",kkk,data+kkk*16);*/		
	}
	kkk = 0;
	/*printf("%lu\n",size_pt);*/
	int padlen = 0;
	/*printf("%c%c\n",ddata[size_pt-2],ddata[size_pt-1]);*/
	if (ddata[size_pt-2] == '1')
		padlen += 10;
	padlen+= ddata[size_pt-1]-48;
	size_t knumber = 0;
	if (padlen == 0)
	        knumber = size_pt - 22;
	else
		knumber = size_pt-22-(16-padlen);
	/*printf("%d,%lu,%lu",padlen,size_pt-22-(16-padlen),knumber);*/
	if(( status = write (fddt, data, knumber)) != -1);
	{
		free (cdata);
		free (data);
		free (mac_hdata);
		free (hdata);
		free (ddata);
		ddata = NULL;
		cdata = NULL;
		hdata = NULL;
		data = NULL;
		mac_hdata = NULL;
		aes_clrkey (aes);
	}
	if (status == -1)
	{
		printf("%s :trouble writing in %s",getprogname (), ptxt_fname);
		perror (getprogname ());
		free (cdata);
		free (data);
		free (mac_hdata);
		free (hdata);
		free (ddata);
		ddata = NULL;
		cdata = NULL;
		hdata = NULL;
		data = NULL;
		mac_hdata = NULL;
		aes_clrkey (aes);

	}

  /*************************************************************************** 
   * Task: Read the ciphertext from the file descriptor fin, decrypt it using
   *       sk, and place the resulting plaintext in a file named ptxt_fname.
   *
   * This procedure basically `undoes' the operations performed by edu_encrypt;
   * it expects a ciphertext featuring the following structure (please refer 
   * to the comments in edu_encrypt.c for more details):
   *
   *
   *         +----+----------------------+--------+
   *         |  Y | HSHA-1 (K_HSHA-1, Y) | padlen |
   *         +----+----------------------+--------+
   *
   * where Y = CBC-AES (K_AES, {plaintext, 0^padlen})
   *       padlen = no. of zero-bytes added to the plaintext to make its
   *                length a multiple of 16.
   * 
   * Moreover, the length of Y (in bytes) is a multiple of 16, the hash value 
   * HSHA-1 (K_HSHA-1, Y) is 20-byte-long, and padlen is a sigle byte.
   * 
   * Reading Y (and then the mac and the pad length) it's a bit tricky: 
   * below we sketch one possible approach, but you are free to implement 
   * this as you wish.
   *
   * The idea is based on the fact that the ciphertext files ends with 
   * 21 bytes (i.e., sha1_hashsize + 1) used up by the HSHA-1 mac and by the 
   * pad length.  Thus, we will repeatedly attempt to perform `long read' of 
   * (aes_blocklen + sha1_hashsize + 2) bytes: once we get at the end of the 
   * ciphertext and only the last chunk of Y has to be read, such `long read'
   * will encounter the end-of-file, at which point we will know where Y ends,
   * and how to finish reading the last bytes of the ciphertext.
   */

  /* use the first part of the symmetric key for the CBC-AES decryption ...*/
  /* ... and the second for the HMAC-SHA1 */

  /* Reading Y */
  /* First, read the IV (Initialization Vector) */

  /* compute the HMAC-SHA1 as you go */

  /* Create plaintext file---may be confidential info, so permission is 0600 */

  /* CBC (Cipher-Block Chaining)---Decryption
   * decrypt the current block and xor it with the previous one 
   */

  /* Recall that we are reading sha_hashsize + 2 bytes ahead: now that 
   * we just consumed aes_blocklen bytes from the front of the buffer, we
   * shift the unused sha_hashsize + 2 bytes left by aes_blocklen bytes 
   */
  
  /* write the decrypted chunk to the plaintext file */

  /* now we can finish computing the HMAC-SHA1 */
  
  /* compare the HMAC-SHA1 we computed with the value read from fin */
  /* NB: if the HMAC-SHA1 mac stored in the ciphertext file does not match 
   * what we just computed, destroy the whole plaintext file! That means
   * that somebody tampered with the ciphertext file, and you should not
   * decrypt it.  Otherwise, the CCA-security is gone.
   */

  /* write the last chunk of plaintext---remember to chop off the trailing
   * zeroes, (how many zeroes were added is specified by the last byte in 
   * the ciphertext (padlen).
   */

}

void 
usage (const char *pname)
{
  printf ("Simple File Decryption Utility\n");
  printf ("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
  printf ("       if a symmetric key sk cannot be found in SK-FILE.\n");
  printf ("       Otherwise, tries to use sk to decrypt the content of\n");
  printf ("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf ("       in PTEXT-FILE; if a decryption problem is encountered\n"); 
  printf ("       after the processing started, PTEXT-FILE is truncated\n");
  printf ("       to zero-length and its previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdctxt;
  char *sk = NULL;
  size_t sk_len = 0;

  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdctxt = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);
      
      exit (-1);
    }
  }   
  else {
    setprogname (argv[0]);

    /* Import symmetric key from argv[1] */
    if (!(sk = import_sk_from_file (&sk, &sk_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);
    /* Enough setting up---let's get to the crypto... */
   /* printf("%lu\n",sk_len);*/
    decrypt_file (argv[3], sk, sk_len, fdctxt);    

    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
    free(sk);
    sk = NULL;
    close (fdctxt);
  }

  return 0;
}
