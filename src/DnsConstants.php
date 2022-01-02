<?php

declare(strict_types=1);

namespace Sztyup\Dns;

use Sztyup\Dns\Meta\OptCodes\DAU;
use Sztyup\Dns\RecordTypes\ResourceRecord;

class DnsConstants
{
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

    public const QR_QUERY                 = 0b0000000000000000;
    public const QR_RESPONSE              = 0b1000000000000000;
    public const OPCODE_STANDARD_QUERY    = 0b0000000000000000;
    public const OPCODE_INVERSE_QUERY     = 0b0000100000000000;
    public const OPCODE_STATUS            = 0b0001000000000000;
    public const OPCODE_NOTIFY            = 0b0010000000000000;
    public const OPCODE_UPDATE            = 0b0010100000000000;
    public const OPCODE_STATEFUL          = 0b0011000000000000;
    public const FLAG_AUTHORITATIVE       = 0b0000010000000000;
    public const FLAG_TRUNCATED           = 0b0000001000000000;
    public const FLAG_RECURSION_DESIRED   = 0b0000000100000000;
    public const FLAG_RECURSION_AVAILABLE = 0b0000000010000000;
    public const FLAG_AUTHENTIC_DATA      = 0b0000000000100000;
    public const FLAG_CHECKING_DISABLED   = 0b0000000000010000;
    public const RCODE_MASK               = 0b0000000000001111;

    public const CLASS_IN     = 1;
    public const CLASS_CHAOS  = 3;
    public const CLASS_HESIOD = 4;
    public const CLASS_NONE   = 254;
    public const CLASS_ANY    = 255;

    public const CLASSES = [
        self::CLASS_IN     => 'IN',
        self::CLASS_CHAOS  => 'CH',
        self::CLASS_HESIOD => 'HS',
        self::CLASS_NONE   => 'NONE',
        self::CLASS_ANY    => 'ANY',
    ];

    public const OPCODES = [
        0 => self::OPCODE_STANDARD_QUERY,
        1 => self::OPCODE_INVERSE_QUERY,
        2 => self::OPCODE_STATUS,
        4 => self::OPCODE_NOTIFY,
        5 => self::OPCODE_UPDATE,
        6 => self::OPCODE_STATEFUL,
    ];

    /** @var class-string<ResourceRecord>[] */
    public const RECORD_TYPES = [
        1     => RecordTypes\Common\A::class,
        2     => RecordTypes\Common\NS::class,
        5     => RecordTypes\Common\CNAME::class,
        6     => RecordTypes\Common\SOA::class,
        12    => RecordTypes\Common\PTR::class,
        15    => RecordTypes\Common\MX::class,
        16    => RecordTypes\Common\TXT::class,
        28    => RecordTypes\Common\AAAA::class,
        41    => RecordTypes\OPT::class,
        43    => RecordTypes\DNSSEC\DS::class,
        46    => RecordTypes\DNSSEC\RRSIG::class,
        47    => RecordTypes\DNSSEC\NSEC::class,
        48    => RecordTypes\DNSSEC\DNSKEY::class,
        50    => RecordTypes\DNSSEC\NSEC3::class,
        51    => RecordTypes\DNSSEC\NSEC3PARAM::class,
        59    => RecordTypes\DNSSEC\CDS::class,
        60    => RecordTypes\DNSSEC\CDNSKEY::class,
    ];

    public static function getRecordName(int $typeId): string
    {
        $type = self::RECORD_TYPES[$typeId] ?? null;

        if ($type === null) {
            return 'TYPE' . $typeId;
        }

        return $type::getName();
    }

    public const OPT_CODES = [
        5 => DAU::class,
    ];

    public const ERROR_TYPES = [
        0  => ['NoError', 'No Error', '[RFC1035]',],
        1  => ['FormErr', 'Format Error', '[RFC1035]',],
        2  => ['ServFail', 'Server Failure', '[RFC1035]',],
        3  => ['NXDomain', 'Non-Existent Domain', '[RFC1035]',],
        4  => ['NotImp', 'Not Implemented', '[RFC1035]',],
        5  => ['Refused', 'Query Refused', '[RFC1035]',],
        6  => ['YXDomain', 'Name Exists when it should not', '[RFC2136][RFC6672]',],
        7  => ['YXRRSet', 'RR Set Exists when it should not', '[RFC2136]',],
        8  => ['NXRRSet', 'RR Set that should exist does not', '[RFC2136]',],
        9  => ['NotAuth', 'Not Authorized', '[RFC8945]',],
        10 => ['NotZone', 'Name not contained in zone', '[RFC2136]',],
        11 => ['DSOTYPENI', 'DSO-TYPE Not Implemented', '[RFC8490]',],
        16 => ['BADVERS', 'Bad OPT Version', '[RFC6891]',],
        17 => ['BADKEY', 'Key not recognized', '[RFC8945]',],
        18 => ['BADTIME', 'Signature out of time window', '[RFC8945]',],
        19 => ['BADMODE', 'Bad TKEY Mode', '[RFC2930]',],
        20 => ['BADNAME', 'Duplicate key name', '[RFC2930]',],
        21 => ['BADALG', 'Algorithm not supported', '[RFC2930]',],
        22 => ['BADTRUNC', 'Bad Truncation', '[RFC8945]',],
        23 => ['BADCOOKIE', 'Bad/missing Server Cookie', '[RFC7873]',],
    ];

    public const ROOT_SERVERS = [
        'a' => ['198.41.0.4', '2001:503:ba3e::2:30'],
        'b' => ['199.9.14.201', '2001:500:200::b'],
        'c' => ['192.33.4.12', '2001:500:2::c'],
        'd' => ['199.7.91.13', '2001:500:2d::d'],
        'e' => ['192.203.230.10', '2001:500:a8::e'],
        'f' => ['192.5.5.241', '2001:500:2f::f'],
        'g' => ['192.112.36.4', '2001:500:12::d0d'],
        'h' => ['198.97.190.53', '2001:500:1::53'],
        'i' => ['192.36.148.17', '2001:7fe::53'],
        'j' => ['192.58.128.30', '2001:503:c27::2:30'],
        'k' => ['193.0.14.129', '2001:7fd::1'],
        'l' => ['199.7.83.42', '2001:500:9f::42'],
        'm' => ['202.12.27.33', '2001:dc3::35'],
    ];
}
