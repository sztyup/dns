<?php

declare(strict_types=1);

namespace Sztyup\Dns;

use Sztyup\Dns\RecordTypes\OPT;

class QueryBuilder
{
    public function build(
        string $domain,
        int    $recordType,
        int    $class = DnsConstants::CLASS_IN
    ): Message {
        $message                   = new Message();
        $message->qr               = 0; // query
        $message->opcode           = 0; // Standard query
        $message->recursionRequest = true;

        $message->questions[] = Question::createFrom($domain, $recordType, $class);

        $message->additionalRecords[] = OPT::create(0, true);

        return $message;
    }
}
