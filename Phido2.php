<?php 

/* Copyright (c) 2016 Saul St John */

namespace Phido2;

class Phido2 
{
    public function __construct($rpDisplayName, $rpServer)
    {
        $this->rpDisplayName = $rpDisplayName;
        $this->rpServer = $rpServer;
    }

    public function getParams($user, $existing = [])
    {
        return json_encode(array(
            'rpDisplayName' => $this->rpDisplayName,
            'userDisplayName' => $user,
            'accountName' => $user . '@' . $this->rpServer,
            'challenge' => base64_encode(openssl_random_pseudo_bytes(20)),
            'existing' => $existing
        ));
    }

    public function validateCredential($paramJs, $credential)
    {
        //pass
    }

    public function validateAssertion($paramsJs, $assertion, $pkeyJs)
    {
        $params = json_decode($paramsJs);

        $pkey = json_decode($pkeyJs);

        if ('RS256' != $pkey->alg) {
            throw new Exception('unsupported algorithm: ' . $pkey->alg);
        }

        $aData = base64_decode(strtr(
            $assertion->signature->authnrData,
            '-_', '+/'
        ));

        $cData = base64_decode(strtr(
            $assertion->signature->clientData,
            '-_', '+/'
        ));

        $assertionChallenge = 
            base64_decode(json_decode(trim($cData, "\0"))->challenge);
        $paramChallenge = base64_decode($params->challenge);

        if (0 != strcmp($assertionChallenge, $paramChallenge)) {
            throw new Exception('assertion challenge incorrect');
        }

        $signedData = $aData . hash('sha256', $cData, true);
        $assertionSig = 
            base64_decode(strtr($assertion->signature->signature, "-_", "+/"));

        $pk_rsid = openssl_pkey_get_public(self::pemify($pkey->n, $pkey->e));

        if (false === $pk_rsid) {
            throw new Exception('openssl_pkey_get_public failed');
        }

        $result = openssl_verify(
            $signedData,
            $assertionSig,
            $pk_rsid,
            OPENSSL_ALGO_SHA256
        );

        openssl_pkey_free($pk_rsid);
        if (0 == $result) {
            throw new Exception('invalid signature');
        }
        if (1 == $result) {
            return true;
        }
        throw new Exception('error validating signature');
    }

    private function pemify($n, $e)
    {
        $data = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A'
            . 'MIIBCgKCAQEA'
            . strtr($n, '-_', '+/')
            . 'ID'
            . strtr($e, '-_', '+/');
            
        return "-----BEGIN PUBLIC KEY-----\r\n"
            . wordwrap($data, 64, "\r\n", true)
            . "\r\n-----END PUBLIC KEY-----";
    }
}
