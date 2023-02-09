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

use DateTime;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Certificate;
use phpseclib3\File\X509;
use web_eid\ocsp_php\exceptions\OcspCertificateException;
use web_eid\ocsp_php\maps\OcspBasicResponseMap;
use web_eid\ocsp_php\util\AsnUtil;

class OcspBasicResponse
{
    private array $ocspBasicResponse = [];

    public function __construct(array $ocspBasicResponse)
    {
        $this->ocspBasicResponse = $ocspBasicResponse;
    }

    public function getResponses(): array
    {
        return $this->ocspBasicResponse["tbsResponseData"]["responses"];
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public function getCertificates(): array
    {
        $certificatesArr = [];
        if (isset($this->ocspBasicResponse["certs"])) {
            foreach ($this->ocspBasicResponse["certs"] as $cert) {
                $x509 = new X509();
                /*
				We need to DER encode each responder certificate array as there exists some
				more loading in X509->loadX509 method, which is not executed when loading just basic array.
				For example without this the publicKey would not be in PEM format and X509->getPublicKey()
				will throw error. It also maps out the extensions from BIT STRING
				*/
                $x509->loadX509(ASN1::encodeDER($cert, Certificate::MAP));
                $certificatesArr[] = $x509;
            }
            unset($x509);
        }

        return $certificatesArr;
    }

    public function getSignature(): string
    {
        $signature = $this->ocspBasicResponse["signature"];
        return pack("c*", ...array_slice(unpack("c*", $signature), 1));
    }

    public function getProducedAt(): DateTime
    {
        return new DateTime(
            $this->ocspBasicResponse["tbsResponseData"]["producedAt"]
        );
    }

    public function getThisUpdate(): DateTime
    {
        return new DateTime($this->getResponses()[0]["thisUpdate"]);
    }

    public function getNextUpdate(): ?DateTime
    {
        if (isset($this->getResponses()[0]["nextUpdate"])) {
            return new DateTime($this->getResponses()[0]["nextUpdate"]);
        }
        return null;
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public function getSignatureAlgorithm(): string
    {
        $algorithm = $this->ocspBasicResponse["signatureAlgorithm"]["algorithm"];

        if (substr_count('.', $algorithm) > 2) {
            $decode = $mapping = ['type' => ASN1::TYPE_OBJECT_IDENTIFIER, 'content' => $algorithm];
            $algorithm = ASN1::asn1map($decode, $mapping);
        }

        $algorithm = strtolower($algorithm);

        if (false !== ($pos = strpos($algorithm, "sha3-"))) {
            return substr($algorithm, $pos, 8);
        }
        if (false !== ($pos = strpos($algorithm, "sha"))) {
            return substr($algorithm, $pos, 6);
        }

        throw new OcspCertificateException(
            "Signature algorithm " . $algorithm . " not implemented"
        );
    }

    public function getNonceExtension(): ?string
    {
        $filter = array_filter(
            $this->ocspBasicResponse["tbsResponseData"]["responseExtensions"],
            function ($extension) {
                return AsnUtil::ID_PKIX_OCSP_NONCE ==
                    ASN1::getOID($extension["extnId"]);
            }
        );

        if (isset($filter[0]["extnValue"])) {
            return $filter[0]["extnValue"];
        }

        return null;
    }

    public function getCertID(): array
    {
        $certStatusResponse = $this->getResponses()[0];
        // Translate algorithm name to OID for correct equality check
        $certStatusResponse["certID"]["hashAlgorithm"][
            "algorithm"
        ] = ASN1::getOID(
            $certStatusResponse["certID"]["hashAlgorithm"]["algorithm"]
        );
        return $certStatusResponse["certID"];
    }

    public function getEncodedResponseData(): string
    {
        return ASN1::encodeDER(
            $this->ocspBasicResponse["tbsResponseData"],
            OcspBasicResponseMap::MAP["children"]["tbsResponseData"]
        );
    }
}
