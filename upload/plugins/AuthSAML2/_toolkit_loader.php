<?php

// Load xmlseclibs
$xmlseclibs_srcdir = dirname(__FILE__) . '/libraries/xmlseclibs';
require $xmlseclibs_srcdir . '/XMLSecurityKey.php';
require $xmlseclibs_srcdir . '/XMLSecurityDSig.php';
require $xmlseclibs_srcdir . '/XMLSecEnc.php';
require $xmlseclibs_srcdir . '/Utils/XPath.php';


// Load php-saml
$libDir = dirname(__FILE__) . '/libraries/Saml2/';
$folderInfo = scandir($libDir);
foreach ($folderInfo as $element) {
    if (is_file($libDir.$element) && (substr($element, -4) === '.php')) {
        include_once $libDir.$element;
    }
}
