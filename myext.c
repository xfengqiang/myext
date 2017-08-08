/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2017 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "php_myext.h"

/* PHP Includes */
#include "ext/standard/file.h"
#include "ext/standard/info.h"
#include "ext/standard/php_fopen_wrappers.h"
#include "ext/standard/md5.h"
#include "ext/standard/base64.h"

/* OpenSSL includes */
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>


#define OPENSSL_RAW_DATA 1
#define OPENSSL_ZERO_PADDING 2

ZEND_DECLARE_MODULE_GLOBALS(myext)

/* True global resources - no need for thread safety here */
static int le_myext;

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    //STD_PHP_INI_ENTRY("myext.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_myext_globals, myext_globals)
    //STD_PHP_INI_ENTRY("myext.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_myext_globals, myext_globals)
PHP_INI_END()
*/
/* }}} */

/* Remove the following function when you have successfully modified config.m4
   so that your module can be compiled into PHP, it exists only for testing
   purposes. */

/* Every user-visible function in PHP should document itself in the source */
/* {{{ proto string confirm_myext_compiled(string arg)
   Return a string to confirm that the module is compiled in */
PHP_FUNCTION(confirm_myext_compiled)
{
	char *arg = NULL;
	size_t arg_len, len;
	zend_string *strg;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &arg, &arg_len) == FAILURE) {
		return;
	}

	strg = strpprintf(0, "Congratulations! You have successfully modified ext/%.78s/config.m4. Module %.78s is now compiled into PHP.", "myext", arg);

	RETURN_STR(strg);
}
/* }}} */
/* The previous line is meant for vim and emacs, so it can correctly fold and
   unfold functions in source code. See the corresponding marks just before
   function definition, where the functions purpose is also documented. Please
   follow this convention for the convenience of others editing your code.
*/


/* {{{ php_myext_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_myext_init_globals(zend_myext_globals *myext_globals)
{
//	myext_globals->global_value = 0;
//	myext_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(myext)
{
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_GINIT_FUNCTION
*/
PHP_GINIT_FUNCTION(myext)
{
#if defined(COMPILE_DL_MYEXT) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	myext_globals->errors = NULL;
}
/* }}} */

/* {{{ PHP_GSHUTDOWN_FUNCTION
*/
PHP_GSHUTDOWN_FUNCTION(myext)
{
	if (myext_globals->errors) {
		pefree(myext_globals->errors, 1);
	}
}
/* }}} */


/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(myext)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(myext)
{
#if defined(COMPILE_DL_MYEXT) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(myext)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(myext)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "myext support", "enabled");
	php_info_print_table_header(2, "Version", "1.0.0");
	php_info_print_table_header(2, "Author", "Fankxu");
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ myext_functions[]
 *
 * Every user visible function must have an entry in myext_functions[].
 */
const zend_function_entry myext_functions[] = {
	PHP_FE(confirm_myext_compiled,	NULL)		/* For testing, remove later. */
        PHP_FE(helloWorld, NULL)

        PHP_FE(xencrypt, NULL)
        PHP_FE(xdecrypt, NULL)

	PHP_FE(xencrypt_v2, NULL)
	PHP_FE(xdecrypt_v2, NULL)
	PHP_FE_END	/* Must be the last line in myext_functions[] */
};
/* }}} */

/* {{{ myext_module_entry
 */
zend_module_entry myext_module_entry = {
	STANDARD_MODULE_HEADER,
	"myext",
	myext_functions,
	PHP_MINIT(myext),
	PHP_MSHUTDOWN(myext),
	PHP_RINIT(myext),		/* Replace with NULL if there's nothing to do at request start */
	PHP_RSHUTDOWN(myext),	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(myext),
	PHP_MYEXT_VERSION,
        PHP_MODULE_GLOBALS(myext),
        PHP_GINIT(myext),
	PHP_GSHUTDOWN(myext),
        NULL,
	STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

#ifdef COMPILE_DL_MYEXT
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(myext)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
PHP_FUNCTION(helloWorld) {
	char *arg = NULL;
	int arg_len, len;
	char *strg;
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &arg, &arg_len) == FAILURE) {
		return ;
	} 

	len = spprintf(&strg, 0, "Hello :%s", arg);
	RETURN_STRINGL(strg, len);
}

/*
 * encrypt
 */
char *g_key = "oScGU3fj8m/tDCyvsbEhwI91M1FcwvQqWuFpPoDHlFk=";
char *g_iv = "w2wJCnctEG09danPPI7SxQ==";
char *g_method = "aes-256-cbc";
int g_option = 1;
PHP_FUNCTION(xencrypt) {
	char *encodeStr = NULL;
	int encodeStrLen, len;
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &encodeStr, &encodeStrLen) == FAILURE) {
		return ;
	} 
      
        zval base64_decode_func;
        zval openssl_encrypt_func;
	
	char *func_name="base64_encode";
        func_name = "base64_decode";
        ZVAL_STRINGL(&base64_decode_func, func_name, strlen(func_name));
        func_name = "openssl_encrypt";
	ZVAL_STRINGL(&openssl_encrypt_func, func_name, strlen(func_name));
	
	
	zval params[5];

	zval keyVal, ivVal;
	ZVAL_STRINGL(&keyVal, g_key, strlen(g_key));
	ZVAL_STRINGL(&ivVal, g_iv, strlen(g_iv));
      

        ZVAL_STRINGL(&params[0], encodeStr, encodeStrLen);
	ZVAL_STRINGL(&params[1], g_method, strlen(g_method));
	call_user_function(EG(function_table), NULL, &base64_decode_func, &params[2], 1, &keyVal TSRMLS_CC);
	ZVAL_LONG(&params[3], g_option);
	call_user_function(EG(function_table), NULL, &base64_decode_func, &params[4], 1, &ivVal TSRMLS_CC);	

        //openssl_encrypt($data, 'aes-256-cbc', base64_decode($key), OPENSSL_RAW_DATA, base64_decode($iv));
	zval retVal;
        call_user_function(EG(function_table), NULL, &openssl_encrypt_func, &retVal, 5, params);	
	RETURN_ZVAL(&retVal, 1, 0);
}

PHP_FUNCTION(xdecrypt) {
	char *rawStr = NULL;
	int rawStrLen;
	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &rawStr, &rawStrLen) == FAILURE) {
		return ;
	} 
        
        char *func_name;
        zval base64_decode_func, openssl_decrypt_func;

	func_name = "base64_decode";
	ZVAL_STRINGL(&base64_decode_func, func_name, strlen(func_name));		
	func_name = "openssl_decrypt";
	ZVAL_STRINGL(&openssl_decrypt_func, func_name, strlen(func_name));
      
	zval params[5];
        zval keyVal, ivVal;
	ZVAL_STRINGL(&keyVal, g_key, strlen(g_key));
	ZVAL_STRINGL(&ivVal, g_iv, strlen(g_iv));
        
	//openssl_decrypt($encrypted, 'aes-256-cbc', base64_decode($key), OPENSSL_RAW_DATA, base64_decode($iv));
        ZVAL_STRINGL(&params[0], rawStr, rawStrLen);
	ZVAL_STRINGL(&params[1], g_method, strlen(g_method));
	call_user_function(EG(function_table), NULL, &base64_decode_func, &params[2], 1, &keyVal TSRMLS_CC);
	ZVAL_LONG(&params[3], g_option);	
	call_user_function(EG(function_table), NULL, &base64_decode_func, &params[4], 1, &ivVal TSRMLS_CC);
 
        zval retVal;
	call_user_function(EG(function_table), NULL, &openssl_decrypt_func, &retVal, 5, params);       
        
	RETURN_ZVAL(&retVal, 1, 0);
}

/* Cipher mode info */
struct php_openssl_cipher_mode {
	zend_bool is_aead;
	zend_bool is_single_run_aead;
	int aead_get_tag_flag;
	int aead_set_tag_flag;
	int aead_ivlen_flag;
};

static void php_openssl_load_cipher_mode(struct php_openssl_cipher_mode *mode, const EVP_CIPHER *cipher_type) /* {{{ */
{
	switch (EVP_CIPHER_mode(cipher_type)) {
#ifdef EVP_CIPH_GCM_MODE
		case EVP_CIPH_GCM_MODE:
			mode->is_aead = 1;
			mode->is_single_run_aead = 0;
			mode->aead_get_tag_flag = EVP_CTRL_GCM_GET_TAG;
			mode->aead_set_tag_flag = EVP_CTRL_GCM_SET_TAG;
			mode->aead_ivlen_flag = EVP_CTRL_GCM_SET_IVLEN;
			break;
#endif
#ifdef EVP_CIPH_CCM_MODE
		case EVP_CIPH_CCM_MODE:
			mode->is_aead = 1;
			mode->is_single_run_aead = 1;
			mode->aead_get_tag_flag = EVP_CTRL_CCM_GET_TAG;
			mode->aead_set_tag_flag = EVP_CTRL_CCM_SET_TAG;
			mode->aead_ivlen_flag = EVP_CTRL_CCM_SET_IVLEN;
			break;
#endif
		default:
			memset(mode, 0, sizeof(struct php_openssl_cipher_mode));
	}
}

static int php_openssl_validate_iv(char **piv, size_t *piv_len, size_t iv_required_len,
		zend_bool *free_iv, EVP_CIPHER_CTX *cipher_ctx, struct php_openssl_cipher_mode *mode) /* {{{ */
{
	char *iv_new;

	/* Best case scenario, user behaved */
	if (*piv_len == iv_required_len) {
		return SUCCESS;
	}

	if (mode->is_aead) {
		if (EVP_CIPHER_CTX_ctrl(cipher_ctx, mode->aead_ivlen_flag, *piv_len, NULL) != 1) {
			php_error_docref(NULL, E_WARNING, "Setting of IV length for AEAD mode failed");
			return FAILURE;
		}
		return SUCCESS;
	}

	iv_new = ecalloc(1, iv_required_len + 1);

	if (*piv_len == 0) {
		/* BC behavior */
		*piv_len = iv_required_len;
		*piv = iv_new;
		*free_iv = 1;
		return SUCCESS;

	}

	if (*piv_len < iv_required_len) {
		php_error_docref(NULL, E_WARNING,
				"IV passed is only %zd bytes long, cipher expects an IV of precisely %zd bytes, padding with \\0",
				*piv_len, iv_required_len);
		memcpy(iv_new, *piv, *piv_len);
		*piv_len = iv_required_len;
		*piv = iv_new;
		*free_iv = 1;
		return SUCCESS;
	}

	php_error_docref(NULL, E_WARNING,
			"IV passed is %zd bytes long which is longer than the %zd expected by selected cipher, truncating",
			*piv_len, iv_required_len);
	memcpy(iv_new, *piv, iv_required_len);
	*piv_len = iv_required_len;
	*piv = iv_new;
	*free_iv = 1;
	return SUCCESS;

}
/* }}} */

static int php_openssl_cipher_init(const EVP_CIPHER *cipher_type,
		EVP_CIPHER_CTX *cipher_ctx, struct php_openssl_cipher_mode *mode,
		char **ppassword, size_t *ppassword_len, zend_bool *free_password,
		char **piv, size_t *piv_len, zend_bool *free_iv,
		char *tag, int tag_len, zend_long options, int enc)  /* {{{ */
{
	unsigned char *key;
	int key_len, password_len;
	size_t max_iv_len;

	/* check and set key */
	password_len = (int) *ppassword_len;
	key_len = EVP_CIPHER_key_length(cipher_type);
	if (key_len > password_len) {
		key = emalloc(key_len);
		memset(key, 0, key_len);
		memcpy(key, *ppassword, password_len);
		*ppassword = (char *) key;
		*ppassword_len = key_len;
		*free_password = 1;
	} else {
		key = (unsigned char*)*ppassword;
		*free_password = 0;
	}

	max_iv_len = EVP_CIPHER_iv_length(cipher_type);
	if (enc && *piv_len == 0 && max_iv_len > 0 && !mode->is_aead) {
		php_error_docref(NULL, E_WARNING,
				"Using an empty Initialization Vector (iv) is potentially insecure and not recommended");
	}

	if (!EVP_CipherInit_ex(cipher_ctx, cipher_type, NULL, NULL, NULL, enc)) {
		php_openssl_store_errors();
		return FAILURE;
	}
	if (php_openssl_validate_iv(piv, piv_len, max_iv_len, free_iv, cipher_ctx, mode) == FAILURE) {
		return FAILURE;
	}
	if (mode->is_single_run_aead && enc) {
		EVP_CIPHER_CTX_ctrl(cipher_ctx, mode->aead_set_tag_flag, tag_len, NULL);
	} else if (!enc && tag && tag_len > 0) {
		if (!mode->is_aead) {
			php_error_docref(NULL, E_WARNING, "The tag cannot be used because the cipher method does not support AEAD");
		} else if (!EVP_CIPHER_CTX_ctrl(cipher_ctx, mode->aead_set_tag_flag, tag_len, (unsigned char *) tag)) {
			php_error_docref(NULL, E_WARNING, "Setting tag for AEAD cipher decryption failed");
			return FAILURE;
		}
	}
	if (password_len > key_len && !EVP_CIPHER_CTX_set_key_length(cipher_ctx, password_len)) {
		php_openssl_store_errors();
	}
	if (!EVP_CipherInit_ex(cipher_ctx, NULL, NULL, key, (unsigned char *)*piv, enc)) {
		php_openssl_store_errors();
		return FAILURE;
	}
	if (options & OPENSSL_ZERO_PADDING) {
		EVP_CIPHER_CTX_set_padding(cipher_ctx, 0);
	}

	return SUCCESS;
}
/* }}} */
void php_openssl_store_errors()
{
	struct php_openssl_errors *errors;
	int error_code = ERR_get_error();

	if (!error_code) {
		return;
	}

	if (!MYEXT_G(errors)) {
		MYEXT_G(errors) = pecalloc(1, sizeof(struct php_openssl_errors), 1);
	}

	errors = MYEXT_G(errors);

	do {
		errors->top = (errors->top + 1) % ERR_NUM_ERRORS;
		if (errors->top == errors->bottom) {
			errors->bottom = (errors->bottom + 1) % ERR_NUM_ERRORS;
		}
		errors->buffer[errors->top] = error_code;
	} while ((error_code = ERR_get_error()));

}

static int php_openssl_cipher_update(const EVP_CIPHER *cipher_type,
		EVP_CIPHER_CTX *cipher_ctx, struct php_openssl_cipher_mode *mode,
		zend_string **poutbuf, int *poutlen, char *data, size_t data_len,
		char *aad, size_t aad_len, int enc)  /* {{{ */
{
	int i = 0;

	if (mode->is_single_run_aead && !EVP_EncryptUpdate(cipher_ctx, NULL, &i, NULL, (int)data_len)) {
		php_openssl_store_errors();
		php_error_docref(NULL, E_WARNING, "Setting of data length failed");
		return FAILURE;
	}

	if (mode->is_aead && !EVP_CipherUpdate(cipher_ctx, NULL, &i, (unsigned char *)aad, (int)aad_len)) {
		php_openssl_store_errors();
		php_error_docref(NULL, E_WARNING, "Setting of additional application data failed");
		return FAILURE;
	}

	*poutbuf = zend_string_alloc((int)data_len + EVP_CIPHER_block_size(cipher_type), 0);

	if (!EVP_CipherUpdate(cipher_ctx, (unsigned char*)ZSTR_VAL(*poutbuf),
					&i, (unsigned char *)data, (int)data_len)) {
		/* we don't show warning when we fail but if we ever do, then it should look like this:
		if (mode->is_single_run_aead && !enc) {
			php_error_docref(NULL, E_WARNING, "Tag verifycation failed");
		} else {
			php_error_docref(NULL, E_WARNING, enc ? "Encryption failed" : "Decryption failed");
		}
		*/
		php_openssl_store_errors();
		zend_string_release(*poutbuf);
		return FAILURE;
	}

	*poutlen = i;

	return SUCCESS;
}
/* }}} */


//使用c方法实现
PHP_FUNCTION(xencrypt_v2) {
        zend_long options = 0, tag_len = 16;
	char *data, *method, *password, *iv = "", *aad = "";
	zval *tag = NULL;
	size_t data_len, method_len, password_len, iv_len = 0, aad_len = 0;
	const EVP_CIPHER *cipher_type;
	EVP_CIPHER_CTX *cipher_ctx;
	struct php_openssl_cipher_mode mode;
	int i=0, outlen;
	zend_string *outbuf;
	zend_bool free_iv = 0, free_password = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &data, &data_len, &options) == FAILURE) {
		return;
	}

	//PHP_OPENSSL_CHECK_SIZE_T_TO_INT(data_len, data);
	//PHP_OPENSSL_CHECK_SIZE_T_TO_INT(password_len, password);
	//PHP_OPENSSL_CHECK_SIZE_T_TO_INT(aad_len, aad);
	//PHP_OPENSSL_CHECK_LONG_TO_INT(tag_len, tag_len);

	cipher_type = EVP_get_cipherbyname(g_method);
	if (!cipher_type) {
		php_error_docref(NULL, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!cipher_ctx) {
		php_error_docref(NULL, E_WARNING, "Failed to create cipher context");
		RETURN_FALSE;
	}
	php_openssl_load_cipher_mode(&mode, cipher_type);

	zend_string *key_buf=NULL, *iv_buf=NULL;

	key_buf = php_base64_decode((unsigned char*)g_key, strlen(g_key));
	iv_buf = php_base64_decode((unsigned char*)g_iv, strlen(g_iv));
	password = ZSTR_VAL(key_buf);
	password_len = ZSTR_LEN(key_buf);
	iv = ZSTR_VAL(iv_buf);
	iv_len = ZSTR_LEN(iv_buf);

	if (php_openssl_cipher_init(cipher_type, cipher_ctx, &mode,
				&password, &password_len, &free_password,
				&iv, &iv_len, &free_iv, NULL, tag_len, options, 1) == FAILURE ||
			php_openssl_cipher_update(cipher_type, cipher_ctx, &mode, &outbuf, &outlen,
				data, data_len, aad, aad_len, 1) == FAILURE) {
		RETVAL_FALSE;
	} else if (EVP_EncryptFinal(cipher_ctx, (unsigned char *)ZSTR_VAL(outbuf) + outlen, &i)) {
		outlen += i;
		if (options & OPENSSL_RAW_DATA) {
			ZSTR_VAL(outbuf)[outlen] = '\0';
			ZSTR_LEN(outbuf) = outlen;
			RETVAL_STR(outbuf);
		} else {
			zend_string *base64_str;

			base64_str = php_base64_encode((unsigned char*)ZSTR_VAL(outbuf), outlen);
			zend_string_release(outbuf);
			outbuf = base64_str;
			RETVAL_STR(base64_str);
		}
		if (mode.is_aead && tag) {
			zend_string *tag_str = zend_string_alloc(tag_len, 0);

			if (EVP_CIPHER_CTX_ctrl(cipher_ctx, mode.aead_get_tag_flag, tag_len, ZSTR_VAL(tag_str)) == 1) {
				zval_dtor(tag);
				ZSTR_VAL(tag_str)[tag_len] = '\0';
				ZSTR_LEN(tag_str) = tag_len;
				ZVAL_NEW_STR(tag, tag_str);
			} else {
				php_error_docref(NULL, E_WARNING, "Retrieving verification tag failed");
				zend_string_release(tag_str);
				zend_string_release(outbuf);
				RETVAL_FALSE;
			}
		} else if (tag) {
			zval_dtor(tag);
			ZVAL_NULL(tag);
			php_error_docref(NULL, E_WARNING,
					"The authenticated tag cannot be provided for cipher that doesn not support AEAD");
		} else if (mode.is_aead) {
			php_error_docref(NULL, E_WARNING, "A tag should be provided when using AEAD mode");
			zend_string_release(outbuf);
			RETVAL_FALSE;
		}
	} else {
		php_openssl_store_errors();
		zend_string_release(outbuf);
		RETVAL_FALSE;
	}


	if(key_buf) {
	    zend_string_release(key_buf);
	}
	if(iv_buf) {
	   zend_string_release(iv_buf);
	}
	if (free_password) {
		efree(password);
	}
	if (free_iv) {
		efree(iv);
	}
	EVP_CIPHER_CTX_cleanup(cipher_ctx);
	EVP_CIPHER_CTX_free(cipher_ctx);
}


PHP_FUNCTION(xdecrypt_v2)
{
	zend_long options = 0;
	char *data, *method, *password, *iv = "", *tag = NULL, *aad = "";
	size_t data_len,  password_len, iv_len = 0, tag_len = 0, aad_len = 0;
	const EVP_CIPHER *cipher_type;
	EVP_CIPHER_CTX *cipher_ctx;
	struct php_openssl_cipher_mode mode;
	int i = 0, outlen;
	zend_string *outbuf;
	zend_string *base64_str = NULL;
	zend_bool free_iv = 0, free_password = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|l", &data, &data_len, &options) == FAILURE) {
		return;
	}

	//PHP_OPENSSL_CHECK_SIZE_T_TO_INT(data_len, data);
	//PHP_OPENSSL_CHECK_SIZE_T_TO_INT(password_len, password);
	//PHP_OPENSSL_CHECK_SIZE_T_TO_INT(aad_len, aad);
	//PHP_OPENSSL_CHECK_SIZE_T_TO_INT(tag_len, tag);

	method = g_method;
	cipher_type = EVP_get_cipherbyname(method);
	if (!cipher_type) {
		php_error_docref(NULL, E_WARNING, "Unknown cipher algorithm");
		RETURN_FALSE;
	}

	cipher_ctx = EVP_CIPHER_CTX_new();
	if (!cipher_ctx) {
		php_error_docref(NULL, E_WARNING, "Failed to create cipher context");
		RETURN_FALSE;
	}

	php_openssl_load_cipher_mode(&mode, cipher_type);

	if (!(options & OPENSSL_RAW_DATA)) {
		base64_str = php_base64_decode((unsigned char*)data, data_len);
		if (!base64_str) {
			php_error_docref(NULL, E_WARNING, "Failed to base64 decode the input");
			EVP_CIPHER_CTX_free(cipher_ctx);
			RETURN_FALSE;
		}
		data_len = ZSTR_LEN(base64_str);
		data = ZSTR_VAL(base64_str);
	}

	zend_string *key_buf=NULL, *iv_buf=NULL;
        key_buf = php_base64_decode((unsigned char*)g_key, strlen(g_key));
	iv_buf = php_base64_decode((unsigned char*)g_iv, strlen(g_iv));

	password = ZSTR_VAL(key_buf);
	password_len = ZSTR_LEN(key_buf);
	iv = ZSTR_VAL(iv_buf);
	iv_len = ZSTR_LEN(iv_buf);

	if (php_openssl_cipher_init(cipher_type, cipher_ctx, &mode,
				&password, &password_len, &free_password,
				&iv, &iv_len, &free_iv, tag, tag_len, options, 0) == FAILURE ||
			php_openssl_cipher_update(cipher_type, cipher_ctx, &mode, &outbuf, &outlen,
				data, data_len, aad, aad_len, 0) == FAILURE) {
		RETVAL_FALSE;
	} else if (mode.is_single_run_aead ||
			EVP_DecryptFinal(cipher_ctx, (unsigned char *)ZSTR_VAL(outbuf) + outlen, &i)) {
		outlen += i;
		ZSTR_VAL(outbuf)[outlen] = '\0';
		ZSTR_LEN(outbuf) = outlen;
		RETVAL_STR(outbuf);
	} else {
		php_openssl_store_errors();
		zend_string_release(outbuf);
		RETVAL_FALSE;
	}
	
	if(key_buf) {
	   zend_string_release(key_buf);
	}

	if(iv_buf) {
	    zend_string_release(iv_buf);
	}

	if (free_password) {
		efree(password);
	}
	if (free_iv) {
		efree(iv);
	}
	if (base64_str) {
		zend_string_release(base64_str);
	}
	EVP_CIPHER_CTX_cleanup(cipher_ctx);
	EVP_CIPHER_CTX_free(cipher_ctx);
}
/* }}} */
