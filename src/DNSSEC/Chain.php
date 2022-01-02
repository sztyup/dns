<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC;

use Sztyup\Dns\RecordTypes\ResourceRecord;

use function count;
use function in_array;

class Chain
{
    private const DNSSEC_TYPES = [60, 59, 48, 43, 47, 50, 51, 46];

    /** @var Link[] */
    public array $links;

    public function __construct(array $links)
    {
        $this->links = $links;
    }

    public function verify(): void
    {
        foreach ($this->links as $link) {
            $link->verify();
        }
    }

    public function getAnswers(): array
    {
        $records = [];

        foreach ($this->links[count($this->links) - 1]->sets as $type => $set) {
            if (!in_array($type, self::DNSSEC_TYPES, true)) {
                $records[] = $set->records;
            }
        }

        return array_merge([], ...$records);
    }
}
