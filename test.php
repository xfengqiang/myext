<?php
$str="abc";

function testUserFunc($str) {
	debug_zval_dump($str);
	$encrypted = xencrypt($str);
	debug_zval_dump($encrypted);
	
	$encode64 = base64_encode($encrypted);
	echo '加密 base64: '.$encode64."\n";
	$decrypt = xdecrypt($encrypted);
	echo "解密 ret:{$decrypt}\n";
}

function testNative($str) {
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
}

function testRaw() {
$data = 'abc';
$key = 'oScGU3fj8m/tDCyvsbEhwI91M1FcwvQqWuFpPoDHlFk='; //echo base64_encode(openssl_random_pseudo_bytes(32));
$iv = 'w2wJCnctEG09danPPI7SxQ=='; //echo base64_encode(openssl_random_pseudo_bytes(16));
echo '内容: '.$data."\n";

$encrypted = openssl_encrypt($data, 'aes-256-cbc', base64_decode($key), 0, base64_decode($iv));
debug_zval_dump($encrypted);
//$encode64 = base64_encode($encrypted);
$encode64 = $encrypted;
echo '加密: '.$encode64."\n";

$decrypted = openssl_decrypt($encode64, 'aes-256-cbc', base64_decode($key), 0, base64_decode($iv));
echo '解密: '.$decrypted."\n";
}
//helloWorld("fankxu");
//leak();

//USE_ZEND_ALLOC=1 时出现coredump
testNative($str); 
//testRaw();
//testUserFunc($str);
