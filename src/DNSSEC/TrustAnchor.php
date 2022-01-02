<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC;

use DateTime;
use RuntimeException;
use SimpleXMLElement;
use Sztyup\Dns\RecordTypes\DNSSEC\DS;

final class TrustAnchor
{
    public const PATH  = __DIR__ . '/../../trust-anchor/';

    public const XML = self::PATH . 'root-anchors.xml';
    public const P7S = self::PATH . 'root-anchors.p7s';
    public const PEM = self::PATH . 'icannbundle.pem';

    public static function getDS(DateTime $now): DS
    {
        self::validate();

        $element = new SimpleXMLElement(file_get_contents(self::XML));

        foreach ($element->KeyDigest as $key) {
            $from  = new DateTime((string)$key['validFrom']);
            $until = new DateTime((string)$key['validUntil']);

            if ($from < $now && $until > $now) {
                return DS::create(
                    (int)$key->KeyTag,
                    (int)$key->Algorithm,
                    (int)$key->DigestType,
                    hex2bin((string)$key->Digest)
                );
            }
        }

        throw new RuntimeException('No valid key found in the root-anchor');
    }

    public static function validate(): void
    {
        $xml = realpath(self::XML);
        $p7s = realpath(self::P7S);
        $pem = realpath(self::PEM);

        $result = openssl_cms_verify(
            $xml,
            OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY,
            null,
            [$pem],
            null,
            null,
            null,
            $p7s,
            OPENSSL_ENCODING_DER
        );

        if ($result === false) {
            throw new RuntimeException('Root anchor verification failed');
        }
    }
}
