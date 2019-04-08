--TEST--
Verify processing of target application availability messaging
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
var_dump(cptl_app_available($hndl));
cptl_testctl(2);
var_dump(cptl_app_available($hndl));
?>
===END===
--EXPECTF--
===START===
bool(true)

Warning: cptl_app_available(): Target application is not available on device %a
bool(false)
===END===
