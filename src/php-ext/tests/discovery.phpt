--TEST--
Verify MDNS discovery processing for ChromeCast with fixed test data.
--SKIPIF--
<?php
if (!extension_loaded('castptl')) {
    die('castptl custom extension not installed in build');
}
?>
--FILE--
===START===
<?php
/* Check the defined constants */
echo 'const ' . CPTL_INET4 . ', ' . CPTL_INET6 . ', ' . CPTL_INET_ALL . "\n\n";
cptl_testctl(1);
var_dump(cptl_discover(CPTL_INET_ALL, 1));
?>
===END===
--EXPECTF--
===START===
const 1, 2, 3

array(2) {
  [0]=>
  array(5) {
    ["id"]=>
    string(32) "63970hbc22h26b6b2a0492825db8d2f4"
    ["name"]=>
    string(6) "Den TV"
    ["model"]=>
    string(10) "Chromecast"
    ["ipAddr"]=>
    string(11) "10.11.12.13"
    ["port"]=>
    int(8009)
  }
  [1]=>
  array(5) {
    ["id"]=>
    string(32) "6b0h3b26023d232e072a2be28a24b7b7"
    ["name"]=>
    string(16) "TST Chrome Panel"
    ["model"]=>
    string(16) "Chromecast Ultra"
    ["ipAddr"]=>
    string(22) "2016:cd8:4567:2cd0::12"
    ["port"]=>
    int(8009)
  }
}
===END===
