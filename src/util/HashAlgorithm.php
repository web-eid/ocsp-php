<?php

namespace web_eid\ocsp_php\util;

enum HashAlgorithm: string
{
    case SHA1 = "sha1";
    case SHA256 = "sha256";
}
