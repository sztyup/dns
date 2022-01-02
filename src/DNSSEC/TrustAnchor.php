<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC;

use DateTime;
use Exception;
use RuntimeException;
use SimpleXMLElement;
use Sztyup\Dns\RecordTypes\DNSSEC\DS;
use Sztyup\Dns\Utilities\DataFormats;

final class TrustAnchor
{
    public const PATH  = __DIR__ . '/../../trust-anchor/';

    public const XML = self::PATH . 'root-anchors.xml';
    public const P7S = self::PATH . 'root-anchors.p7s';
    public const PEM = self::PATH . 'icannbundle.pem';

    public static function getDS(DateTime $now): DS
    {
        self::validate();

        try {
            $element = new SimpleXMLElement(file_get_contents(self::XML));
        } catch (Exception) {
            throw new RuntimeException('Cannot parse root-anchors.xml file');
        }

        foreach ($element->KeyDigest as $key) {
            $from  = DataFormats::parseAtom((string)$key['validFrom']);
            $until = DataFormats::parseAtom((string)$key['validUntil']);

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
