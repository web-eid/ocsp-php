# ocsp-php

**NB! Please note that the ocsp-php code was moved to web-eid-authtoken-validation-php repository.<br>
We won't be accepting pull requests or responding to issues in this repository anymore. We are happy to accept your proposals in the web-eid-authtoken-validation-php repository: https://github.com/web-eid/web-eid-authtoken-validation-php.**

ocsp-php is a library for PHP for checking if certificates are revoked, by using Online Certificate Status Protocol (OCSP).

This library does not include any HTTP client, you can use cURL for example.

# Quickstart

Complete the steps below to include the library in your project.

A PHP web application that uses Composer to manage packages is needed for running this quickstart.

## Add the library to your project

Install using Composer:

```sh
composer require web-eid/ocsp-php
```

## Loading the certificates

By using **CertificateLoader**, you can load certificates from file or string.

```php
// Loading certificate from file
$certificate = (new CertificateLoader)->fromFile('/path/to/cert.crt')->getCert();

// Loading certificate from string
$certificate = (new CertificateLoader)->fromString('-----BEGIN CERTIFICATE-----MIIEAzCCA...-----END CERTIFICATE-----')->getCert();
```

## Getting the issuer certificate from certificate

The certificate usually contains a URL where you can find certificate of the certificate issuer.

You can use this code to extract this URL from the certificate.

```php
$certLoader = (new CertificateLoader)->fromFile('/path/to/cert.crt');
$issuerCertificateUrl = $certLoader->getIssuerCertificateUrl();
```

`$issuerCertificateUrl` will contain the URL where the issuer certificate can be downloaded. When it is an empty string, that means the issuer certificate URL is not included in the SSL certificate.

## Getting the OCSP responder URL

To check if a SSL Certificate is valid, you need to know the OCSP URL, that is provided by the authority that issued the certificate. This URL can be called to check if the certificate has been revoked.

This URL may be included in the SSL Certificate itself.

You can use this code to extract the OCSP responder URL from the SSL Certificate.

```php
$certLoader = (new CertificateLoader)->fromFile('/path/to/cert.crt');
$ocspResponderUrl = $certLoader->getOcspResponderUrl();
```
When it is an empty string, that means the OCSP responder URL is not included in the SSL Certificate.

## Checking the revocation status of an SSL Certificate

Once you have the SSL Certificate, the issuer certificate, and the OCSP responder URL, you can check whether the SSL certificate has been revoked or is still valid.

```php
$subjectCert = (new CertificateLoader)->fromFile('/path/to/subject.crt')->getCert();
$issuerCert = (new CertificateLoader)->fromFile('/path/to/issuer.crt')->getCert();

// Create the certificateId
$certificateId = (new Ocsp)->generateCertificateId($subjectCert, $issuerCert);

// Build request body
$requestBody = new OcspRequest();
$requestBody->addCertificateId($certificateId);

// Add nonce extension when the nonce feature is enabled,
// otherwise skip this line
$requestBody->addNonceExtension(random_bytes(8));

// Send request to OCSP responder URL
$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, $ocspResponderUrl);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_POST, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, ['Content-Type: ' .Ocsp::OCSP_REQUEST_MEDIATYPE]);
curl_setopt($curl, CURLOPT_POSTFIELDS, $requestBody->getEncodeDer());
$result = curl_exec($curl);
$info = curl_getinfo($curl);
if ($info["http_code"] !== 200) {
    throw new RuntimeException("HTTP status is not 200");
}

// Check the response content type
if ($info["content_type"] != Ocsp::OCSP_RESPONSE_MEDIATYPE) {
    throw new RuntimeException("Content-Type header of the response is wrong");
}

// Decode the raw response from the OCSP Responder
$response = new OcspResponse($result);

// Validate response certificateId
$response->validateCertificateId($certificateId);

// Validate response signature
$response->validateSignature();

// Validate nonce when the nonce feature is enabled,
$basicResponse = $response->getBasicResponse();
if ($requestBody->getNonceExtension() != $basicResponse->getNonceExtension()) {
    throw new RuntimeException("OCSP request nonce and response nonce do not match");
} 

```
`$response` contains instance of the `web_eid\ocsp_php\OcspResponse` class:

* `$response->isRevoked() === false` when the certificate is not revoked
* `$response->isRevoked() === true` when the certificate is revoked (to get revoke reason, call `$response->getRevokeReason()`)
* when `$response->isRevoked()` returns null, then the certificate revoke status is unknown

To get more detailed information from response, you can use:

```php
// Read response status
$response->getStatus();
$basicResponse = $response->getBasicResponse();
```

Following methods can be called with `$basicResponse`:

* `$basicResponse->getResponses()` - returns array of the responses
* `$basicResponse->getCertificates()` - returns array of X.509 certificates (phpseclib3\File\X509)
* `$basicResponse->getSignature()` - returns signature
* `$basicResponse->getProducedAt()` - returns DateTime object
* `$basicResponse->getThisUpdate()` - returns DateTime object
* `$basicResponse->getNextUpdate()` - returns DateTime object (is `null` when `nextUpdate` field does not exist)
* `$basicResponse->getSignatureAlgorithm()` - returns signature algorithm as string (throws exception, when signature algorithm is not implemented)
* `$basicResponse->getNonceExtension()` - returns nonce (when value is `null` then nonce extension does not exist in response)
* `$basicResponse->getCertID()` - returns response certificateID

To get the full response for debugging or logging purposes, use `$response->getResponse()`

# Exceptions

All exceptions are handled by the `web_eid\ocsp_php\exceptions\OcspException` class. To catch these errors, you can enclose your code within try/catch statements:

```php
try {
    // code
} catch (OcspException $e) {
    // exception handler
}
```

# PHPSeclib versioning policy

Starting from version 1.1.0 we adopt a flexible versioning policy for
`phpseclib` and specify the dependency as `3.0.*`. This approach allows our
library integrators to quickly incorporate security patches and minor updates
from `phpseclib`.

## Why we include `composer.lock`

While it is common practice for applications to include a `composer.lock` file
to lock down the specific versions of dependencies used, this is less common
for libraries. However, we have chosen to include `composer.lock` in our
repository to clearly indicate the exact versions of dependencies we have
tested against.

Although our library is designed to work with any minor version of `phpseclib`
within the specified range, the `composer.lock` file ensures that integrators
are aware of the specific version we consider stable and secure. The provided
`composer.lock` is intended to be used as a reference, not as a strict
requirement.

# Code formatting

We are using `Prettier` for code formatting. To install Prettier, use following command:

```
npm install --global prettier @prettier/plugin-php
```
Run command for code formatting:
```
composer fix-php
```

# Testing

Run phpunit in the root directory to run all unit tests.

```
./vendor/bin/phpunit tests
```

