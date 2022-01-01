<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC;

use DateTime;
use phpseclib3\Crypt\Common\PublicKey;
use RuntimeException;
use Sztyup\Dns\DNSSEC\Algorithms\RSASHA1;
use Sztyup\Dns\DNSSEC\Algorithms\RSASHA256;
use Sztyup\Dns\RecordTypes\DNSSEC\DNSKEY;
use Sztyup\Dns\RecordTypes\DNSSEC\RRSIG;
use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\StringStream;

use function strlen;

class SignedSet
{
    public array $records;

    public RRSIG $signature;

    public bool $verified = false;

    /**
     * @param ResourceRecord[] $records
     * @param RRSIG $signature
     */
    public function __construct(array $records, RRSIG $signature)
    {
        if (empty($records)) {
            throw new RuntimeException('Empty signedSet');
        }

        $this->records   = $records;
        $this->signature = $signature;
    }

    public function verify(DNSKEY $dnskey): bool
    {
        if (!$this->signature->validForTime(new DateTime('now'))) {
            throw new RuntimeException('Signature timing problem');
        }

        $key  = $this->getPublicKey($dnskey);
        $data = $this->signature->getCanonicalData();

        $rrset = $this->canonicalOrdering($this->records);
        foreach ($rrset as $record) {
            if (!$this->signature->matchingRecord($record)) {
                throw new RuntimeException('Record is no match for signature');
            }

            $data .= $record->getCanonicalRepresentation($this->signature->originalTTL);
        }

        return $this->verified = $key->verify($data, $this->signature->signature);
    }

    /**
     * @return ResourceRecord[]
     */
    private function canonicalOrdering(array $rrset): array
    {
        usort($rrset, function (ResourceRecord $a, ResourceRecord $b) {
            return strcmp($a->getCanonicalData()->toString(), $b->getCanonicalData()->toString());
        });

        return $rrset;
    }

    private function getPublicKey(DNSKEY $dnskey): PublicKey
    {
        $class = match ($dnskey->algorithm) {
            5       => RSASHA1::class,
            8       => RSASHA256::class,
            default => throw new RuntimeException('Algorithm ' . $dnskey->algorithm . ' not implemented'),
        };

        $algorithm = new $class(new StringStream($dnskey->key), strlen($dnskey->key));

        return $algorithm->toPublicKey();
    }
}
