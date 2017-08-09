<?php
 $str="abc";
debug_zval_dump($str);
$encrypted = xencrypt($str);
debug_zval_dump($encrypted);

$encode64 = base64_encode($encrypted);
echo '加密 base64: '.$encode64."\n";
$decrypt = xdecrypt($encrypted);
echo "解密 ret:{$decrypt}\n";


echo "=======auto base64=====\n";
$encrypted_v2 = xencrypt_v2($str);
echo "xencrypt_v2 ret:".$encrypted_v2."\n";
debug_zval_dump($encrypted_v2);
$decrypt_v2 = xdecrypt_v2($encrypted_v2);
echo "xdecrypt_v2 ret:".$decrypt_v2."\n";


echo "=======decode base64=====\n";
$encrypted_v2 = xencrypt_v2($str, 1);
echo "xencrypt_v2 ret:".base64_encode($encrypted_v2)."\n";
debug_zval_dump($encrypted_v2);
$decrypt_v2 = xdecrypt_v2($encrypted_v2, 1);
echo "xdecrypt_v2 ret:".$decrypt_v2."\n";
