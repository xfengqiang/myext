<?php

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
debug_zval_dump($decrypted);
echo '解密: '.$decrypted."\n";

return ;
#$encrypted = base64_decode($encrypted);
$decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', base64_decode($key), OPENSSL_RAW_DATA, base64_decode($iv));
echo '解密: '.$decrypted."\n";
