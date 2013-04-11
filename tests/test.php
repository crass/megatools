<?php

if ($_GET['action'] == 'json') 
{
  ob_start();
  
  for ($i = 0; $i < 100; $i++)
    echo "Bla bla bla\n";

  header('Content-Length: '.ob_get_length());
  ob_end_flush();
  exit();
}

$PATH = "test.dat";

if (!file_exists($PATH))
{
  header('HTTP/1.1 404 File Not Found');
  exit();
}

$file_len = filesize($PATH);

$off = isset($_GET['off']) ? (int)$_GET['off'] : 0;
$len = isset($_GET['len']) ? (int)$_GET['len'] : $file_len - $off;

if ($off > $file_len || $len == 0)
{
  header('HTTP/1.1 416 Requested Range Not Satisfiable');
  exit();
}

$f = fopen($PATH, "r");
fseek($f, $off);

header('Content-Length: ' . $len);
echo fread($f, $len);

?>
