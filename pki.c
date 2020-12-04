	/*
 * PKI related functions
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include "config.h"
#include <fcntl.h>
#include <assert.h>
#ifdef	WITH_SECURITY
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#endif
#include <libisns/isns.h>
#include "security.h"
#include <libisns/util.h>

#ifdef WITH_SECURITY

/* versions prior to 9.6.8 didn't seem to have these */
#if OPENSSL_VERSION_NUMBER < 0x00906080L
# define EVP_MD_CTX_init(c)	do { } while (0)
# define EVP_MD_CTX_cleanup(c)	do { } while (0)
#endif
#if OPENSSL_VERSION_NUMBER < 0x00906070L
# define i2d_DSA_PUBKEY		i2d_DSA_PUBKEY_backwards

static int	i2d_DSA_PUBKEY_backwards(DSA *, unsigned char **);
#endif
/* OpenSSL 1.1 made a lot of structures opaque, so we need to
 * define the 1.1 wrappers in previous versions. */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_PKEY_base_id(o)  ((o)->type)
#define EVP_PKEY_get0_DSA(o) ((o)->pkey.dsa)
static EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    EVP_MD_CTX *ctx = OPENSSL_malloc(sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(ctx);
    return ctx;
}

static void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}
void DSA_get0_key(const DSA *d,
                  const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}
BN_GENCB *BN_GENCB_new(void)
{
    return OPENSSL_malloc(sizeof(BN_GENCB));
}
void BN_GENCB_free(BN_GENCB *cb)
{
    OPENSSL_free(cb);
}
#else
/* EVP_dss1 is now gone completely, so just use EVP_sha1 instead. */
#define EVP_dss1 EVP_sha1
#endif


static int	isns_openssl_init = 0;

static int	isns_dsasig_verify(isns_security_t *ctx,
				isns_principal_t *peer,
				buf_t *pdu,
				const struct isns_authblk *);
static int	isns_dsasig_sign(isns_security_t *ctx,
				isns_principal_t *peer,
				buf_t *pdu,
				struct isns_authblk *);
static EVP_PKEY *isns_dsasig_load_private_pem(isns_security_t *ctx,
				const char *filename);
static EVP_PKEY *isns_dsasig_load_public_pem(isns_security_t *ctx,
				const char *filename);
static DSA *	isns_dsa_load_params(const char *);


/*
 * Create a DSA security context
 */
isns_security_t *
isns_create_dsa_context(void)
{
	isns_security_t	*ctx;

	if (!isns_openssl_init) {
#if OPENSSL_API_COMPAT < 0x10100000L
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_ciphers();
		OpenSSL_add_all_digests();
#endif
		isns_openssl_init = 1;
	}

	ctx = isns_calloc(1, sizeof(*ctx));

	ctx->is_name = "DSA";
	ctx->is_type = ISNS_AUTH_TYPE_SHA1_DSA;
	ctx->is_replay_window = isns_config.ic_auth.replay_window;
	ctx->is_timestamp_jitter = isns_config.ic_auth.timestamp_jitter;

	ctx->is_verify = isns_dsasig_verify;
	ctx->is_sign = isns_dsasig_sign;
	ctx->is_load_private = isns_dsasig_load_private_pem;
	ctx->is_load_public = isns_dsasig_load_public_pem;

	isns_debug_auth("Created DSA authentication context\n");
	return ctx;
}

/*
 * DSA signature generation and verification
 */
static void
isns_message_digest(EVP_MD_CTX *md, const buf_t *pdu,
		const struct isns_authblk *blk)
{
	uint64_t	stamp;

	EVP_DigestUpdate(md, buf_head(pdu), buf_avail(pdu));

	/* The RFC doesn't say which pieces of the
	 * message should be hashed.
	 * We make an educated guess.
	 */
	stamp = htonll(blk->iab_timestamp);
	EVP_DigestUpdate(md, &stamp, sizeof(stamp));
}

static void
isns_dsasig_report_errors(const char *msg, isns_print_fn_t *fn)
{
	unsigned long	code;

	fn("%s - OpenSSL errors follow:\n", msg);
	while ((code = ERR_get_error()) != 0)
		fn("> %s: %s\n",
			ERR_func_error_string(code),
			ERR_reason_error_string(code));
}

int
isns_dsasig_sign(__attribute__((unused))isns_security_t *ctx,
			isns_principal_t *peer,
			buf_t *pdu,
			struct isns_authblk *blk)
{
	static unsigned char signature[1024];
	unsigned int	sig_len = sizeof(signature);
	EVP_MD_CTX	*md_ctx;
	EVP_PKEY	*pkey;
	const BIGNUM    *priv_key = NULL;
	int		err;

	if ((pkey = peer->is_key) == NULL)
		return 0;

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_DSA) {
		isns_debug_message(
			"Incompatible public key (spi=%s)\n",
			peer->is_name);
		return 0;
	}
	if (EVP_PKEY_size(pkey) > (int)sizeof(signature)) {
		isns_error("isns_dsasig_sign: signature buffer too small\n");
		return 0;
	}
	DSA_get0_key(EVP_PKEY_get0_DSA(pkey), NULL, &priv_key);
	if (priv_key == NULL) {
		isns_error("isns_dsasig_sign: oops, seems to be a public key\n");
		return 0;
	}

	isns_debug_auth("Signing messages with spi=%s, DSA/%u\n",
			peer->is_name, EVP_PKEY_bits(pkey));

	md_ctx = EVP_MD_CTX_new();
	EVP_SignInit(md_ctx, EVP_dss1());
	isns_message_digest(md_ctx, pdu, blk);
	err = EVP_SignFinal(md_ctx,
				signature, &sig_len,
				pkey);
	EVP_MD_CTX_free(md_ctx);

	if (err == 0) {
		isns_dsasig_report_errors("EVP_SignFinal failed", isns_error);
		return 0;
	}

	blk->iab_sig = signature;
	blk->iab_sig_len = sig_len;
	return 1;
}

int
isns_dsasig_verify(__attribute__((unused))isns_security_t *ctx,
			isns_principal_t *peer,
			buf_t *pdu,
			const struct isns_authblk *blk)
{
	EVP_MD_CTX	*md_ctx;
	EVP_PKEY	*pkey;
	int		err;

	if ((pkey = peer->is_key) == NULL)
		return 0;

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_DSA) {
		isns_debug_message(
			"Incompatible public key (spi=%s)\n",
			peer->is_name);
		return 0;
	}

	md_ctx = EVP_MD_CTX_new();
	EVP_VerifyInit(md_ctx, EVP_dss1());
	isns_message_digest(md_ctx, pdu, blk);
	err = EVP_VerifyFinal(md_ctx,
			blk->iab_sig, blk->iab_sig_len,
			pkey);
	EVP_MD_CTX_free(md_ctx);
	
	if (err == 0) {
		isns_debug_auth("*** Incorrect signature ***\n");
		return 0;
	}
	if (err < 0) {
		isns_dsasig_report_errors("EVP_VerifyFinal failed", isns_error);
		return 0;
	}

	isns_debug_message("Good signature from %s\n",
			peer->is_name?: "<server>");
	return 1;
}

EVP_PKEY *
isns_dsasig_load_private_pem(__attribute__((unused))isns_security_t *ctx,
		const char *filename)
{
	EVP_PKEY	*pkey;
	FILE		*fp;

	if (!(fp = fopen(filename, "r"))) {
		isns_error("Unable to open DSA keyfile %s: %m\n",
				filename);
		return 0;
	}

	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return pkey;
}

EVP_PKEY *
isns_dsasig_load_public_pem(__attribute__((unused))isns_security_t *ctx,
		const char *filename)
{
	EVP_PKEY	*pkey;
	FILE		*fp;

	if (!(fp = fopen(filename, "r"))) {
		isns_error("Unable to open DSA keyfile %s: %m\n",
				filename);
		return 0;
	}

	pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	if (pkey == NULL) {
		isns_dsasig_report_errors("Error loading DSA public key",
				isns_error);
	}

	fclose(fp);
	return pkey;
}

EVP_PKEY *
isns_dsa_decode_public(const void *ptr, size_t len)
{
	const unsigned char *der = ptr;
	EVP_PKEY *evp;
	DSA	*dsa;

	/* Assigning ptr to a temporary variable avoids a silly
	 * compiled warning about type-punning. */
	dsa = d2i_DSA_PUBKEY(NULL, &der, len);
	if (dsa == NULL)
		return NULL;

	evp = EVP_PKEY_new();
	EVP_PKEY_assign_DSA(evp, dsa);
	return evp;
}

int
isns_dsa_encode_public(EVP_PKEY *pkey, void **ptr, size_t *len)
{
	int	bytes;

	*ptr = NULL;
	bytes = i2d_DSA_PUBKEY(EVP_PKEY_get0_DSA(pkey), (unsigned char **) ptr);
	if (bytes < 0)
		return 0;

	*len = bytes;
	return 1;
}

EVP_PKEY *
isns_dsa_load_public(const char *name)
{
	return isns_dsasig_load_public_pem(NULL, name);
}

int
isns_dsa_store_private(const char *name, EVP_PKEY *key)
{
	FILE	*fp;
	int	rv, fd;

	if ((fd = open(name, O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0) {
		isns_error("Cannot save DSA key to %s: %m\n", name);
		return 0;
	}

	if (!(fp = fdopen(fd, "w"))) {
		isns_error("fdopen(%s): %m\n", name);
		close(fd);
		return 0;
	}

	rv = PEM_write_PrivateKey(fp, key, NULL, NULL, 0, 0, NULL);
	fclose(fp);

	if (rv == 0)
		isns_dsasig_report_errors("Failed to store private key",
				isns_error);

	return rv;
}

int
isns_dsa_store_public(const char *name, EVP_PKEY *key)
{
	FILE	*fp;
	int	rv;

	if (!(fp = fopen(name, "w"))) {
		isns_error("Unable to open %s: %m\n", name);
		return 0;
	}

	rv = PEM_write_PUBKEY(fp, key);
	fclose(fp);

	if (rv == 0)
		isns_dsasig_report_errors("Failed to store public key",
				isns_error);

	return rv;
}


/*
 * DSA key generation
 */
EVP_PKEY *
isns_dsa_generate_key(void)
{
	EVP_PKEY *pkey;
	DSA	*dsa = NULL;

	if (!(dsa = isns_dsa_load_params(isns_config.ic_dsa.param_file)))
		goto failed;

	if (!DSA_generate_key(dsa)) {
		isns_dsasig_report_errors("Failed to generate DSA key",
				isns_error);
		goto failed;
	}

	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_DSA(pkey, dsa);
	return pkey;

failed:
	if (dsa)
		DSA_free(dsa);
	return NULL;
}

DSA *
isns_dsa_load_params(const char *filename)
{
	FILE	*fp;
	DSA	*dsa;

	if (!filename) {
		isns_error("Cannot generate key - no DSA parameter file\n");
		return NULL;
	}
	if (!(fp = fopen(filename, "r"))) {
		isns_error("Unable to open %s: %m\n", filename);
		return NULL;
	}

	dsa = PEM_read_DSAparams(fp, NULL, NULL, NULL);
	fclose(fp);

	if (dsa == NULL) {
		isns_dsasig_report_errors("Error loading DSA parameters",
				isns_error);
	}

	return dsa;
}

/*
 * write one 'status' character to stdout
 */
static void
write_status_byte(int ch)
{
	static int	stdout_fd = 1;	/* fileno(stdout) */
	char		buf[2];
	int		res;

	/*
	 * We don't actually care about the return value here, since
	 * we are just dumping a status byte to stdout, but
	 * some linux distrubutions set the warn_unused_result attribute
	 * for the write() API, so we might as well use the return value
	 * to make sure the write command isn't broken.
	 */
	assert(ch);
	buf[0] = ch;
	buf[1] = '\0';
	res = write(stdout_fd, buf, 1);
	assert(res == 1);
}

static void
isns_dsa_param_gen_callback(int stage,
		__attribute__((unused))int index,
		__attribute__((unused))void *dummy)
{
	if (stage == 0)
		write_status_byte('+');
	else if (stage == 1)
		write_status_byte('.');
	else if (stage == 2)
		write_status_byte('/');
}

int
isns_dsa_init_params(const char *filename)
{
	FILE	*fp;
	DSA	*dsa;
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	BN_GENCB	*cb;
#endif
	const int dsa_key_bits = 1024;

	if (access(filename, R_OK) == 0)
		return 1;

	isns_mkdir_recursive(isns_dirname(filename));
	if (!(fp = fopen(filename, "w"))) {
		isns_error("Unable to open %s: %m\n", filename);
		return 0;
	}

	isns_notice("Generating DSA parameters; this may take a while\n");
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	cb = BN_GENCB_new();
	BN_GENCB_set_old(cb, (void (*)(int, int, void *)) isns_dsa_param_gen_callback, NULL);
	dsa = DSA_new();
	if (!DSA_generate_parameters_ex(dsa, dsa_key_bits, NULL, 0, NULL, NULL, cb)) {
		DSA_free(dsa);
		dsa = NULL;
	}
	BN_GENCB_free(cb);
#else
	dsa = DSA_generate_parameters(dsa_key_bits, NULL, 0,
			NULL, NULL, isns_dsa_param_gen_callback, NULL);
#endif
	write_status_byte('\n');

	if (dsa == NULL) {
		isns_dsasig_report_errors("Error generating DSA parameters",
				isns_error);
		fclose(fp);
		return 0;
	}

	if (!PEM_write_DSAparams(fp, dsa)) {
		isns_dsasig_report_errors("Error writing DSA parameters",
				isns_error);
		DSA_free(dsa);
		fclose(fp);
		return 0;
	}
	DSA_free(dsa);
	fclose(fp);
	return 1;
}

/*
 * Make sure the authentication key is present.
 */
int
isns_dsa_init_key(const char *filename)
{
	char	pubkey_path[1024];
	EVP_PKEY *pkey;

	isns_mkdir_recursive(isns_dirname(filename));
	snprintf(pubkey_path, sizeof(pubkey_path),
				"%s.pub", filename);
	if (access(filename, R_OK) == 0
	 && access(pubkey_path, R_OK) == 0)
		return 1;

	if (!(pkey = isns_dsa_generate_key())) {
		isns_error("Failed to generate AuthKey\n");
		return 0;
	}

	if (!isns_dsa_store_private(filename, pkey)) {
		isns_error("Unable to write private key to %s\n", filename);
		return 0;
	}
	isns_notice("Stored private key in %s\n", filename);

	if (!isns_dsa_store_public(pubkey_path, pkey)) {
		isns_error("Unable to write public key to %s\n", pubkey_path);
		return 0;
	}
	isns_notice("Stored private key in %s\n", pubkey_path);

	return 1;
}

/*
 * Simple keystore - this is a flat directory, with
 * public key files using the SPI as their name.
 */
typedef struct isns_simple_keystore isns_simple_keystore_t;
struct isns_simple_keystore {
	isns_keystore_t	sc_base;
	char *		sc_dirpath;
};

/*
 * Load a DSA key from the cert store
 * In fact, this will load RSA keys as well.
 */
static EVP_PKEY *
__isns_simple_keystore_find(isns_keystore_t *store_base,
		const char *name, size_t namelen)
{
	isns_simple_keystore_t *store = (isns_simple_keystore_t *) store_base;
	char		*pathname;
	size_t		capacity;
	EVP_PKEY	*result;

	/* Refuse to open key files with names
	 * that refer to parent directories */
	if (memchr(name, '/', namelen) || name[0] == '.')
		return NULL;

	capacity = strlen(store->sc_dirpath) + 2 + namelen;
	pathname = isns_malloc(capacity);
	if (!pathname)
		isns_fatal("Out of memory.");
	snprintf(pathname, capacity,
			"%s/%.*s", store->sc_dirpath,
			(int) namelen, name);
	if (access(pathname, R_OK) < 0) {
		isns_free(pathname);
		return NULL;
	}
	result = isns_dsasig_load_public_pem(NULL, pathname);
	isns_free(pathname);
	return result;
}

isns_keystore_t *
isns_create_simple_keystore(const char *dirname)
{
	isns_simple_keystore_t *store;

	store = isns_calloc(1, sizeof(*store));
	store->sc_base.ic_name = "simple key store";
	store->sc_base.ic_find = __isns_simple_keystore_find;
	store->sc_dirpath = isns_strdup(dirname);

	return (isns_keystore_t *) store;
}

#if OPENSSL_VERSION_NUMBER < 0x00906070L
#undef i2d_DSA_PUBKEY

int
i2d_DSA_PUBKEY_backwards(DSA *dsa, unsigned char **ptr)
{
	unsigned char *buf;
	int len;

	len = i2d_DSA_PUBKEY(dsa, NULL);
	if (len < 0)
		return 0;

	*ptr = buf = OPENSSL_malloc(len);
	return i2d_DSA_PUBKEY(dsa, &buf);
}
#endif

#endif /* WITH_SECURITY */
