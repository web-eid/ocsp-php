<?php

/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

declare(strict_types=1);

namespace web_eid\ocsp_php;

use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use UnexpectedValueException;
use web_eid\ocsp_php\exceptions\OcspResponseDecodeException;
use web_eid\ocsp_php\exceptions\OcspVerifyFailedException;
use web_eid\ocsp_php\maps\OcspBasicResponseMap;
use web_eid\ocsp_php\maps\OcspResponseMap;

class OcspResponse
{
    private array $ocspResponse = [];
    private string $revokeReason = "";

    public function __construct(string $encodedBER)
    {
        $decoded = ASN1::decodeBER($encodedBER);
        if (!$decoded[0]) {
            throw new OcspResponseDecodeException();
        }

        $this->ocspResponse = ASN1::asn1map(
            $decoded[0],
            OcspResponseMap::MAP,
            array('response' => function ($encoded) {
                return ASN1::asn1map(ASN1::decodeBER($encoded)[0], OcspBasicResponseMap::MAP);
            })            
        );

    }

    public function getBasicResponse(): OcspBasicResponse
    {
        if (Ocsp::ID_PKIX_OCSP_BASIC_STRING != $this->ocspResponse['responseBytes']['responseType']) {
            throw new UnexpectedValueException('responseType is not "id-pkix-ocsp-basic" but is ' . $this->ocspResponse['responseBytes']['responseType']);
        }

        if (!$this->ocspResponse['responseBytes']['response']) {
            throw new UnexpectedValueException('Could not decode OcspResponse->responseBytes->responseType');
        }

        return new OcspBasicResponse($this->ocspResponse['responseBytes']['response']);
    }

    public function getStatus(): string
    {
        return $this->ocspResponse['responseStatus'];
    }

    public function getRevokeReason(): string
    {
        return $this->revokeReason;
    }
    
    public function isRevoked()
    {
        $basicResponse = $this->getBasicResponse();
        if (isset($basicResponse->getResponses()[0]['certStatus']['good'])) {
            return false;
        }
        if (isset($basicResponse->getResponses()[0]['certStatus']['revoked'])) {
            $revokedStatus = $basicResponse->getResponses()[0]['certStatus']['revoked'];
            // Check revoke reason
            if (isset($revokedStatus['revokedReason'])) {
                $this->revokeReason = $revokedStatus['revokedReason'];
            }
            return true;
        }
        return null;
    }

    private function validateResponseSignature(OcspBasicResponse $basicResponse, X509 $certificate)
    {
        // get public key from responder certificate in order to verify signature on response
        $publicKey = $certificate->getPublicKey()->withHash($basicResponse->getSignatureAlgorithm());

        // verify response data
        $encodedTbsResponseData = $basicResponse->getEncodedResponseData();
        $signature = $basicResponse->getSignature();

        if (!$publicKey->verify($encodedTbsResponseData, $signature)) {
            throw new OcspVerifyFailedException("OCSP response signature is not valid");
        }

    }
    
    public function verify(array $requestCertificateId)
    {

        $basicResponse = $this->getBasicResponse();

        // Must be one response
        if (count($basicResponse->getResponses()) != 1) {
            throw new OcspVerifyFailedException("OCSP response must contain one response, received " . count($basicResponse->getResponses()) . " responses instead");
        }

        $certStatusResponse = $basicResponse->getResponses()[0];

        // Translate algorithm name to OID for correct equality check
        $certStatusResponse['certID']['hashAlgorithm']['algorithm'] = ASN1::getOID($certStatusResponse['certID']['hashAlgorithm']['algorithm']);

        if ($requestCertificateId != $certStatusResponse['certID']) {
            throw new OcspVerifyFailedException("OCSP responded with certificate ID that differs from the requested ID");
        }

        // At least on cert must exist in responder
        if (count($basicResponse->getCertificates()) < 1) {
            throw new OcspVerifyFailedException("OCSP response must contain the responder certificate, but non was provided");
        }

        // Validate responder certificate signature
        $responderCert = $basicResponse->getCertificates()[0];
        $this->validateResponseSignature($basicResponse, $responderCert);

    }



}