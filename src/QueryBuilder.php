<?php

declare(strict_types=1);

namespace Sztyup\Dns;

use Exception;
use RuntimeException;
use Sztyup\Dns\RecordTypes\OPT;

class QueryBuilder
{
    public function build(
        string $domain,
        int    $recordType,
        int    $class = DnsConstants::CLASS_IN
    ): Message {
        $message         = new Message($this->generateID());
        $message->qr     = 0; // query
        $message->opcode = 0; // Standard query

        $message->recursionRequest = true;

        $message->questions[] = new Question($domain, $recordType, $class);

        $message->additionalRecords[] = OPT::create(0, true);

        return $message;
    }

    private function generateID(): int
    {
        try {
            return random_int(0, 2 ** 16 - 1);
        } catch (Exception) {
            throw new RuntimeException('Cannot generate sufficiently random transaction ID, aborting.');
        }
    }
}
