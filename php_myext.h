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

#ifndef PHP_MYEXT_H
#define PHP_MYEXT_H


extern zend_module_entry myext_module_entry;
#define phpext_myext_ptr &myext_module_entry




#define PHP_MYEXT_VERSION "0.1.0" /* Replace with version number for your extension */

#ifdef PHP_WIN32
#	define PHP_MYEXT_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_MYEXT_API __attribute__ ((visibility("default")))
#else
#	define PHP_MYEXT_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include <openssl/err.h>

struct php_openssl_errors {
        int buffer[ERR_NUM_ERRORS];
        int top;
        int bottom;
};




ZEND_BEGIN_MODULE_GLOBALS(myext)
     struct php_openssl_errors *errors;
ZEND_END_MODULE_GLOBALS(myext)


/* Always refer to the globals in your function as MYEXT_G(variable).
   You are encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/
#define MYEXT_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(myext, v)

#if defined(ZTS) && defined(COMPILE_DL_MYEXT)
ZEND_TSRMLS_CACHE_EXTERN()
#endif


void php_openssl_store_errors();

PHP_GINIT_FUNCTION(myext);
PHP_GSHUTDOWN_FUNCTION(myext);

PHP_FUNCTION(helloWorld);

PHP_FUNCTION(xencrypt);
PHP_FUNCTION(xdecrypt);

PHP_FUNCTION(xencrypt_v2);
PHP_FUNCTION(xdecrypt_v2);

#endif	/* PHP_MYEXT_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
