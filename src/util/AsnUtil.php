<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
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

namespace web_eid\ocsp_php\util;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\SubjectPublicKeyInfo;

class AsnUtil
{
    public const ID_PKIX_OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";

    public static function loadOIDs(): void
    {
        ASN1::loadOIDs([
            "id-pkix-ocsp-nonce" => self::ID_PKIX_OCSP_NONCE,
            "id-sha1" => "1.3.14.3.2.26",
            "id-sha256" => "2.16.840.1.101.3.4.2.1",
            "sha256WithRSAEncryption" => "1.2.840.113549.1.1.11",
            "qcStatements(3)" => "1.3.6.1.5.5.7.1.3",
            "street" => "2.5.4.9",
            "id-pkix-ocsp-basic" => "1.3.6.1.5.5.7.48.1.1",
            "id-pkix-ocsp" => "1.3.6.1.5.5.7.48.1",
            "secp384r1" => "1.3.132.0.34",
            "id-pkix-ocsp-archive-cutoff" => "1.3.6.1.5.5.7.48.1.6",
            "id-pkix-ocsp-nocheck" => "1.3.6.1.5.5.7.48.1.5",
        ]);
    }

    public static function extractKeyData(string $publicKey): string
    {
        $extractedBER = ASN1::extractBER($publicKey);
        $decodedBER = ASN1::decodeBER($extractedBER);
        $subjectPublicKey = ASN1::asn1map(
            $decodedBER[0],
            SubjectPublicKeyInfo::MAP
        )["subjectPublicKey"];
        // Remove first byte
        return pack("c*", ...array_slice(unpack("c*", $subjectPublicKey), 1));
    }

    public static function decodeNonceExtension(array $ocspExtensions): ?string
    {
        $nonceExtension = current(
            array_filter(
                $ocspExtensions,
                function ($extension) {
                    return self::ID_PKIX_OCSP_NONCE == ASN1::getOID($extension["extnId"]);
                }
            )
        );
        if (!$nonceExtension || !isset($nonceExtension["extnValue"])) {
            return null;
        }

        $nonceValue = $nonceExtension["extnValue"];

        $decoded = ASN1::decodeBER($nonceValue);
        if (is_array($decoded)) {
            // The value was DER-encoded, it is required to be an octet string.
            $nonceString = ASN1::asn1map($decoded[0], ['type' => ASN1::TYPE_OCTET_STRING]);
            return is_string($nonceString) ? $nonceString : null;
        }

        // The value was not DER-encoded, return it as-is.
        return $nonceValue;
    }

}
