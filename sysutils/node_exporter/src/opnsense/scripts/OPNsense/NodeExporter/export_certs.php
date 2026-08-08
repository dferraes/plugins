#!/usr/local/bin/php
<?php

/*
 *    Copyright (C) 2026 David Ferraes
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Trust\Cert;
use OPNsense\Trust\Ca;
use OPNsense\Trust\Store as CertStore;

$dir = '/usr/local/etc/node_exporter';
$cert_filename = $dir . '/cert.pem';
$pkey_filename = $dir . '/key.pem';
$ca_filename = $dir . '/client_ca.pem';

if (!is_dir($dir)) {
    mkdir($dir, 0700, true);
}
chmod($dir, 0755);  /* nobody tiene que poder atravesarlo */

/* Se reescriben en cada arranque: si el usuario deselecciona un certificado, el
 * archivo viejo NO debe quedarse atrás sirviendo material obsoleto. */
foreach ([$cert_filename, $pkey_filename, $ca_filename] as $f) {
    if (is_file($f)) {
        unlink($f);
    }
}

$configObj = Config::getInstance()->object();
/* El modelo monta en //OPNsense/NodeExporter y los campos cuelgan DIRECTO de ahí.
 * El "general" de los ids del formulario es $internalModelName del controlador,
 * no un nodo de config.xml — leer $configObj->OPNsense->NodeExporter->general
 * devuelve null y el script no escribe nada, en silencio. */
$general = $configObj->OPNsense->NodeExporter ?? null;
if ($general === null || (string)$general->tls_enabled !== '1') {
    return;
}

/* Certificado de servidor (+ su cadena, para que el cliente pueda validarlo). */
$cert_refid = (string)($general->tls_certificate ?? '');
if (!empty($cert_refid)) {
    foreach ((new Cert())->cert->iterateItems() as $cert) {
        if ($cert_refid !== (string)$cert->refid) {
            continue;
        }
        $cert_content = str_replace("\n\n", "\n", str_replace("\r", "", base64_decode((string)$cert->crt)));
        $pkey_content = str_replace("\n\n", "\n", str_replace("\r", "", base64_decode((string)$cert->prv)));
        if (!empty((string)$cert->caref)) {
            $ca = CertStore::getCaChain((string)$cert->caref);
            if ($ca) {
                $cert_content .= "\n" . $ca;
            }
        }
        file_put_contents($cert_filename, $cert_content);
        file_put_contents($pkey_filename, $pkey_content);
        /* node_exporter corre como nobody:nobody (ver su rc): con 0600 root no
         * podría leer la llave y arrancaría fallando. */
        foreach ([$cert_filename, $pkey_filename] as $f) {
            chown($f, 'nobody');
            chgrp($f, 'nobody');
            chmod($f, 0400);
        }
    }
}

/* CA que firma a los clientes autorizados. Sin esto node_exporter sirve TLS pero
 * acepta a cualquiera: es la pieza que convierte "cifrado" en "autenticado". */
$ca_refid = (string)($general->tls_client_ca ?? '');
if (!empty($ca_refid)) {
    foreach ((new Ca())->ca->iterateItems() as $ca) {
        if ($ca_refid !== (string)$ca->refid) {
            continue;
        }
        $ca_content = str_replace("\n\n", "\n", str_replace("\r", "", base64_decode((string)$ca->crt)));
        file_put_contents($ca_filename, $ca_content);
        chown($ca_filename, 'nobody');
        chgrp($ca_filename, 'nobody');
        chmod($ca_filename, 0400);
    }
}
