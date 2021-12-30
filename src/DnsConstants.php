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

    public const OPCODES = [
        0 => self::OPCODE_STANDARD_QUERY,
        1 => self::OPCODE_INVERSE_QUERY,
        2 => self::OPCODE_STATUS,
        4 => self::OPCODE_NOTIFY,
        5 => self::OPCODE_UPDATE,
        6 => self::OPCODE_STATEFUL,
    ];

    public const CLASSES = [
        self::CLASS_IN     => 'IN',
        self::CLASS_CHAOS  => 'CH',
        self::CLASS_HESIOD => 'HS',
        self::CLASS_NONE   => 'NONE',
        self::CLASS_ANY    => 'ANY',
    ];

    /** @var ResourceRecord[] */
    public const RECORD_TYPES = [
        1     => \Sztyup\Dns\RecordTypes\A::class,
        2     => \Sztyup\Dns\RecordTypes\NS::class,
        3     => \Sztyup\Dns\RecordTypes\MD::class,
        4     => \Sztyup\Dns\RecordTypes\MF::class,
        5     => \Sztyup\Dns\RecordTypes\CNAME::class,
        6     => \Sztyup\Dns\RecordTypes\SOA::class,
        7     => \Sztyup\Dns\RecordTypes\MB::class,
        8     => \Sztyup\Dns\RecordTypes\MG::class,
        9     => \Sztyup\Dns\RecordTypes\MR::class,
        11    => \Sztyup\Dns\RecordTypes\WKS::class,
        12    => \Sztyup\Dns\RecordTypes\PTR::class,
        13    => \Sztyup\Dns\RecordTypes\HINFO::class,
        14    => \Sztyup\Dns\RecordTypes\MINFO::class,
        15    => \Sztyup\Dns\RecordTypes\MX::class,
        16    => \Sztyup\Dns\RecordTypes\TXT::class,
        17    => \Sztyup\Dns\RecordTypes\RP::class,
        18    => \Sztyup\Dns\RecordTypes\AFSDB::class,
        19    => \Sztyup\Dns\RecordTypes\X25::class,
        20    => \Sztyup\Dns\RecordTypes\ISDN::class,
        21    => \Sztyup\Dns\RecordTypes\RT::class,
        24    => \Sztyup\Dns\RecordTypes\SIG::class,
        25    => \Sztyup\Dns\RecordTypes\KEY::class,
        26    => \Sztyup\Dns\RecordTypes\PX::class,
        27    => \Sztyup\Dns\RecordTypes\GPOS::class,
        28    => \Sztyup\Dns\RecordTypes\AAAA::class,
        29    => \Sztyup\Dns\RecordTypes\LOC::class,
        30    => \Sztyup\Dns\RecordTypes\NXT::class,
        31    => \Sztyup\Dns\RecordTypes\EID::class,
        32    => \Sztyup\Dns\RecordTypes\NIMLOC::class,
        33    => \Sztyup\Dns\RecordTypes\SRV::class,
        34    => \Sztyup\Dns\RecordTypes\ATMA::class,
        35    => \Sztyup\Dns\RecordTypes\NAPTR::class,
        36    => \Sztyup\Dns\RecordTypes\KX::class,
        37    => \Sztyup\Dns\RecordTypes\CERT::class,
        39    => \Sztyup\Dns\RecordTypes\DNAME::class,
        40    => \Sztyup\Dns\RecordTypes\SINK::class,
        41    => \Sztyup\Dns\RecordTypes\OPT::class,
        42    => \Sztyup\Dns\RecordTypes\APL::class,
        43    => \Sztyup\Dns\RecordTypes\DS::class,
        44    => \Sztyup\Dns\RecordTypes\SSHFP::class,
        45    => \Sztyup\Dns\RecordTypes\IPSECKEY::class,
        46    => \Sztyup\Dns\RecordTypes\RRSIG::class,
        47    => \Sztyup\Dns\RecordTypes\NSEC::class,
        48    => \Sztyup\Dns\RecordTypes\DNSKEY::class,
        49    => \Sztyup\Dns\RecordTypes\DHCID::class,
        50    => \Sztyup\Dns\RecordTypes\NSEC3::class,
        51    => \Sztyup\Dns\RecordTypes\NSEC3PARAM::class,
        52    => \Sztyup\Dns\RecordTypes\TLSA::class,
        53    => \Sztyup\Dns\RecordTypes\SMIMEA::class,
        55    => \Sztyup\Dns\RecordTypes\HIP::class,
        56    => \Sztyup\Dns\RecordTypes\NINFO::class,
        57    => \Sztyup\Dns\RecordTypes\RKEY::class,
        58    => \Sztyup\Dns\RecordTypes\TALINK::class,
        59    => \Sztyup\Dns\RecordTypes\CDS::class,
        60    => \Sztyup\Dns\RecordTypes\CDNSKEY::class,
        61    => \Sztyup\Dns\RecordTypes\OPENPGPKEY::class,
        62    => \Sztyup\Dns\RecordTypes\CSYNC::class,
        63    => \Sztyup\Dns\RecordTypes\ZONEMD::class,
        64    => \Sztyup\Dns\RecordTypes\SVCB::class,
        65    => \Sztyup\Dns\RecordTypes\HTTPS::class,
        99    => \Sztyup\Dns\RecordTypes\SPF::class,
        100   => \Sztyup\Dns\RecordTypes\UINFO::class,
        101   => \Sztyup\Dns\RecordTypes\UID::class,
        102   => \Sztyup\Dns\RecordTypes\GID::class,
        103   => \Sztyup\Dns\RecordTypes\UNSPEC::class,
        104   => \Sztyup\Dns\RecordTypes\NID::class,
        105   => \Sztyup\Dns\RecordTypes\L32::class,
        106   => \Sztyup\Dns\RecordTypes\L64::class,
        107   => \Sztyup\Dns\RecordTypes\LP::class,
        108   => \Sztyup\Dns\RecordTypes\EUI48::class,
        109   => \Sztyup\Dns\RecordTypes\EUI64::class,
        249   => \Sztyup\Dns\RecordTypes\TKEY::class,
        250   => \Sztyup\Dns\RecordTypes\TSIG::class,
        251   => \Sztyup\Dns\RecordTypes\IXFR::class,
        252   => \Sztyup\Dns\RecordTypes\AXFR::class,
        253   => \Sztyup\Dns\RecordTypes\MAILB::class,
        254   => \Sztyup\Dns\RecordTypes\MAILA::class,
        256   => \Sztyup\Dns\RecordTypes\URI::class,
        257   => \Sztyup\Dns\RecordTypes\CAA::class,
        258   => \Sztyup\Dns\RecordTypes\AVC::class,
        259   => \Sztyup\Dns\RecordTypes\DOA::class,
        260   => \Sztyup\Dns\RecordTypes\AMTRELAY::class,
        32768 => \Sztyup\Dns\RecordTypes\TA::class,
        32769 => \Sztyup\Dns\RecordTypes\DLV::class,
    ];

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
