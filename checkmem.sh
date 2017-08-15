#!/bin/sh
export ZEND_DONT_UNLOAD_MODULES=1 
export USE_ZEND_ALLOC=0 
#valgrind --leak-check=full --suppressions=suppresion.log --show-reachable=yes --log-file=php.log --track-origins=yes /opt/soft/php7_debug/bin/php -dextension=myext.so /tmp/foo.php
#valgrind --leak-check=full --show-reachable=yes --log-file=php.log --track-origins=yes /opt/soft/php7_debug/bin/php  test.php
valgrind --suppressions=./suppressions.txt --leak-check=full --show-reachable=yes --log-file=php.log --track-origins=yes /opt/soft/php7_debug/bin/php  a.php
