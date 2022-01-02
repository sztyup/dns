<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC;

use RuntimeException;
use Sztyup\Dns\RecordTypes\DNSSEC\DNSKEY;
use Sztyup\Dns\RecordTypes\DNSSEC\DS;

use function array_key_exists;

class Link
{
    public string $zone;

    /** @var SignedSet[] */
    public array $sets;

    public DS $parent;

    public function __construct(string $zone, array $sets, DS $parent)
    {
        $this->zone   = $zone;
        $this->sets   = $sets;
        $this->parent = $parent;
    }

    public function verify(): void
    {
        $this->ensureRequiredSets();

        $digestVerified = false;
        /** @var DNSKEY $dnskey */
        foreach ($this->sets[DNSKEY::getId()]->records as $dnskey) {
            if ($this->parent->matchingKey($dnskey)) {
                $this->verifyKeyDigest($dnskey);
                $digestVerified = true;
            }

            if ($dnskey->zoneKey) {
                foreach ($this->sets as $set) {
                    if ($set->signature->signerName !== $this->zone) {
                        throw new RuntimeException('Zone name difference: ');
                    }

                    if (!$set->verified && $set->signature->matchingKey($dnskey)) {
                        $set->verify($dnskey);
                    }
                }
            }
        }

        if (!$digestVerified) {
            throw new RuntimeException('Could not verify digest');
        }

        foreach ($this->sets as $set) {
            if (!$set->verified) {
                throw new RuntimeException('Could not verify set: ' . $set->signature->typeCovered);
            }
        }
    }

    private function verifyKeyDigest(DNSKEY $key): void
    {
        $calculated = match ($this->parent->digestType) {
            1       => sha1($key->getDigestString(), true),
            2       => hash('sha256', $key->getDigestString(), true),
            4       => hash('sha384', $key->getDigestString(), true),
            default => throw new RuntimeException('Unsupported DS Digest algo: ' . $this->parent->digestType)
        };

        if (!hash_equals($this->parent->digest, $calculated)) {
            throw new RuntimeException('Invalid digest');
        }
    }

    private function ensureRequiredSets(): void
    {
        if (!array_key_exists(DNSKEY::getId(), $this->sets)) {
            throw new RuntimeException('Link (' . $this->zone . ') does not have any DNSKEY needed for verification');
        }
    }
}
