--TEST--
Verify simulated processing of a cast device keepalive ping.
--SKIPIF--
<?php
if (!extension_loaded('castptl')) {
    die('castptl custom extension not installed in build');
}
?>
--FILE--
===START===
<?php
cptl_testctl(1);
$hndl = cptl_device_connect('localhost', 8009);
var_dump(cptl_device_ping($hndl));
?>
===END===
--EXPECTF--
===START===
bool(true)
===END===
