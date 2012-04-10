/* Copyright (C) 2012 Daiki Ueno <ueno@unixuser.org>

   This file is part of gpass-export.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#include <config.h>
#include <gcrypt.h>
#include <gpgme.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <byteswap.h>
#include <string.h>
#include "getpass.h"
#include "xvasprintf.h"

#define PREFIX "GPassFile version 1.1.0"
static const uint8_t iv[] = { 5, 23, 1, 123, 12, 3, 54, 94 };

static uint32_t
unpack_varnum (const uint8_t *buf, size_t bufsize, uint8_t **endptr)
{
  const uint8_t *p = buf;
  uint32_t retval = 0;
  int base = 1;

  for (p = buf; p < buf + bufsize; p++, base *= 0x80)
    {
      if ((*p & 0x80) == 0)
	{
	  retval += base * *p;
	  *endptr = (uint8_t *) p + 1;
	  break;
	}
      retval += base * (*p & 0x7f);
    }
#ifdef WORDS_BIGENDIAN
  retval = bswap_32 (retval);
#endif
  return retval;
}

static uint32_t
unpack_fixnum (const uint8_t *buf, size_t bufsize, uint8_t **endptr)
{
  uint32_t retval;

  if (bufsize < 4)
    return 0;

  retval = *(uint32_t *) buf;
#ifdef WORDS_BIGENDIAN
  retval = bswap_32 (retval);
#endif
  *endptr = (uint8_t *) buf + 4;
  return retval;
}

static gpgme_error_t
_gpgme_data_print (gpgme_data_t data, const char *fmt, ...)
{
  va_list ap;
  char *str;
  gpgme_error_t err;

  va_start (ap, fmt);
  str = xvasprintf (fmt, ap);
  va_end (ap);

  err = gpgme_data_write (data, str, strlen (str));
  free (str);
  return err;
}

static gpgme_error_t
passfunc (void *hook, const char *uid_hint, const char *passphrase_info,
	  int prev_was_bad, int fd)
{
  char *password = getpass ("Export password: ");
  write (fd, password, strlen (password));
  write (fd, "\n", 1);
  return 0;
}

static bool
parse (const uint8_t *buf, size_t bufsize)
{
  gpgme_ctx_t ctx;
  gpgme_data_t plain, cipher;
  gpgme_error_t err;
  uint8_t *p = (uint8_t *) buf;
  size_t ciphersize, nwritten;

  gpgme_data_new (&plain);

  if (memcmp (buf, PREFIX, sizeof (PREFIX) - 1) != 0)
    {
      fprintf (stderr, "Prefix mismatch - probably wrong password\n");
      return false;
    }
  p += sizeof (PREFIX) - 1;

  _gpgme_data_print (plain, "%%rec: Account\n%%key: Login\n\n");

  while (p < buf + bufsize)
    {
      uint8_t *entry_end, *q;
      uint32_t n, m;
      time_t t;
      struct tm *tm;
      char *str, tstr[11];
      bool expires;

      /* id and parent */
      p += 8;

      /* type */
      if (p >= buf + bufsize)
	break;
      n = unpack_fixnum (p, bufsize - (p - buf), &p);

      if (p + n >= buf + bufsize)
	break;

      m = unpack_fixnum (p + n, bufsize - (p + n - buf), &q);
      entry_end = q + m;
      if (memcmp (p, "general", n) != 0)
	{
	  p = entry_end;
	  continue;
	}
      p = q;

      /* name */
      n = unpack_varnum (p, bufsize - (p - buf), &p);
      str = strndup ((char *) p, n);
      _gpgme_data_print (plain, "Name: %s\n", str);
      free (str);
      p += n;
      if (p >= entry_end)
	break;

      /* description */
      n = unpack_varnum (p, bufsize - (p - buf), &p);
      if (n > 0)
	{
	  str = strndup ((char *) p, n);
	  _gpgme_data_print (plain, "Description: %s\n", str);
	  free (str);
	}
      p += n;
      if (p >= entry_end)
	break;

      /* creation-time */
      n = unpack_varnum (p, bufsize - (p - buf), &p);
      t = (time_t) n;
      tm = localtime (&t);
      
      strftime (tstr, sizeof (tstr), "%Y-%m-%d", tm);
      _gpgme_data_print (plain, "CreatedAt: %s\n", tstr);
      
      if (p >= entry_end)
	break;

      /* modification-time */
      n = unpack_varnum (p, bufsize - (p - buf), &p);
      t = (time_t) n;
      tm = localtime (&t);
      
      strftime (tstr, sizeof (tstr), "%Y-%m-%d", tm);
      _gpgme_data_print (plain, "LastModified: %s\n", tstr);

      if (p >= entry_end)
	break;

      /* expiration */
      expires = (bool) *p++;
      if (p >= entry_end)
	break;

      /* expiration-time */
      n = unpack_varnum (p, bufsize - (p - buf), &p);
      if (expires)
	{
	  t = (time_t) n;
	  tm = localtime (&t);
      
	  strftime (tstr, sizeof (tstr), "%Y-%m-%d", tm);
	  _gpgme_data_print (plain, "ExpiresAt: %s\n", tstr);
	}

      if (p >= entry_end)
	break;

      /* username */
      n = unpack_varnum (p, bufsize - (p - buf), &p);
      if (n > 0)
	{
	  str = strndup ((char *) p, n);
	  _gpgme_data_print (plain, "Login: %s\n", str);
	  free (str);
	}
      p += n;
      if (p >= entry_end)
	break;

      /* password */
      n = unpack_varnum (p, bufsize - (p - buf), &p);
      if (n > 0)
	{
	  str = strndup ((char *) p, n);
	  _gpgme_data_print (plain, "Password: %s\n", str);
	  free (str);
	}
      p += n;

      _gpgme_data_print (plain, "\n");
      p = entry_end;
    }

  gpgme_new (&ctx);

  if (getenv ("GPG_AGENT_INFO") == NULL)
    gpgme_set_passphrase_cb (ctx, passfunc, NULL);

  gpgme_data_seek (plain, 0, SEEK_SET);
  gpgme_data_new (&cipher);
  err = gpgme_op_encrypt (ctx, NULL, 0, plain, cipher);
  gpgme_release (ctx);
  gpgme_data_release (plain);
  if (gpgme_err_code (err) != GPG_ERR_NO_ERROR)
    {
      fprintf (stderr, "Failed to encrypt: %s", gpgme_strerror (err));
      gpgme_data_release (cipher);
      return false;
    }

  p = gpgme_data_release_and_get_mem (cipher, &ciphersize);
  nwritten = 0;
  while (nwritten < ciphersize)
    {
      ssize_t retval = write (fileno (stdout),
			      p + nwritten,
			      ciphersize - nwritten);
      if (retval <= 0)
	break;
      nwritten += retval;
    }
  free (p);
  return true;
}

static bool
decrypt (const char *filename, char *password)
{
  gcry_cipher_hd_t cipher;
  int fd;
  uint8_t *key;
  size_t keysize;
  uint8_t *buf, *p;
  size_t blocksize;
  size_t nblocks;
  gcry_error_t err;

  /* read */
  fd = open (filename, O_RDONLY);
  if (fd < 0)
    {
      fprintf (stderr, "Can't open file %s: %s", filename, strerror (errno));
      return false;
    }

  err = gcry_cipher_algo_info (GCRY_CIPHER_BLOWFISH,
			       GCRYCTL_GET_BLKLEN,
			       0,
			       &blocksize);
  if (err)
    {
      fprintf (stderr, "Can't get block size: %s\n", gcry_strerror (err));
      return false;
    }
  buf = gcry_malloc_secure (blocksize);

  nblocks = 0;
  while (1)
    {
      ssize_t retval;

      p = buf + blocksize * nblocks;

      retval =  read (fd, p, blocksize);
      if (retval < 0)
	{
	  fprintf (stderr, "Error reading file: %s\n", strerror (errno));
	  gcry_free (buf);
	  return false;
	}

      if (retval == 0)
	break;

      nblocks++;
      buf = gcry_realloc (buf, blocksize * (nblocks + 1));
    }

  /* decrypt buffer */
  err = gcry_cipher_open (&cipher,
			  GCRY_CIPHER_BLOWFISH,
			  GCRY_CIPHER_MODE_CBC,
			  0);
  if (err)
    {
      fprintf (stderr, "Can't open cipher: %s\n", gcry_strerror (err));
      return false;
    }

  keysize = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
  key = gcry_malloc_secure (keysize);

  gcry_md_hash_buffer (GCRY_MD_SHA1, key, password, strlen (password));

  err = gcry_cipher_setkey (cipher, key, keysize);
  gcry_free (key);
  if (err)
    {
      fprintf (stderr, "Can't set key: %s\n", gcry_strerror (err));
      return false;
    }

  err = gcry_cipher_setiv (cipher, iv, sizeof (iv));
  if (err)
    {
      fprintf (stderr, "Can't set IV: %s\n", gcry_strerror (err));
      return false;
    }

  err = gcry_cipher_decrypt (cipher,
			     buf,
			     blocksize * nblocks,
			     NULL,
			     0);
  gcry_cipher_close (cipher);
  if (err)
    {
      fprintf (stderr, "Failed to decrypt: %s\n", gcry_strerror (err));
      gcry_free (buf);
      return false;
    }

  parse (buf, blocksize * nblocks);

  return true;
}

int
main (int argc, char **argv)
{
  char *password;
  bool retval;
  gpgme_error_t err;

  if (argc != 2)
    {
      fprintf (stderr, "Usage: %s ~/.gpass/passwords.gps > passwords.rec.gpg\n",
	       argv[0]);
      exit (2);
    }

  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fprintf (stderr, "libgcrypt version mismatch\n");
      exit (2);
    }

  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  gpgme_check_version (NULL);
  err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
  if (gpgme_err_code (err) != GPG_ERR_NO_ERROR)
    {
      fprintf (stderr, "OpenPGP is not usable with GPGME\n");
      exit (2);
    }

  password = getpass ("Password: ");
  if (!password)
    {
      fprintf (stderr, "Can't get password\n");
      exit (2);
    }

  retval = decrypt (argv[1], password);
  free (password);
  if (!retval)
    {
      fprintf (stderr, "Decryption failed\n");
      exit (2);
    }

  return 0;
}
