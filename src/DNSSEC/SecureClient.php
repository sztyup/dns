<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC;

use DateTime;
use RuntimeException;
use Sztyup\Dns\Client;
use Sztyup\Dns\DnsConstants;
use Sztyup\Dns\Message;
use Sztyup\Dns\RecordTypes\Common\A;
use Sztyup\Dns\RecordTypes\Common\NS;
use Sztyup\Dns\RecordTypes\DNSSEC\DNSKEY;
use Sztyup\Dns\RecordTypes\DNSSEC\DS;
use Sztyup\Dns\Utilities\DataFormats;

class SecureClient
{
    private Client $client;

    public function __construct()
    {
        $this->client = new Client();
    }

    public function query(string $domain, int $typeId): array
    {
        $chain = $this->buildChain($domain, $typeId);

        $chain->verify();

        return $chain->getAnswers();
    }

    public function buildChain(string $domain, int $typeId): Chain
    {
        $nsCandidates = array_column(DnsConstants::ROOT_SERVERS, 0);

        $ds = TrustAnchor::getDS(new DateTime());

        $links = [];
        foreach (DataFormats::domainChain($domain) as $zone) {
            $message = $this->queryByNsCandidates($domain, $typeId, $nsCandidates);

            $sets = $message->findSignedSets();

            if (empty($sets[DNSKEY::getId()])) {
                $sets += $this->queryByNsCandidates($zone, DNSKEY::getId(), $nsCandidates)->findSignedSets();
            }

            if (empty($sets[DS::getId()])) {
                $sets += $this->queryByNsCandidates($domain, DS::getId(), $nsCandidates)->findSignedSets();
            }

            $link = new Link($zone, $sets, $ds);

            $link->verify();

            $links[] = $link;

            $nsCandidates = $this->processNsCandidates($message);

            if ($message->authoritative) { // Reached the authoritative response
                return new Chain($links);
            }

            if (empty($nsCandidates)) { // Probably reached the end of the chain
                throw new RuntimeException('No NS records received for ' . $zone);
            }

            if (!isset($link->sets[DS::getId()])) { // Cannot go further securely
                return new Chain($links);
            }

            $ds = $link->sets[DS::getId()]->records[0] ?? null;

            if ($ds === null) { // Cannot go further securely
                return new Chain($links);
            }
        }

        throw new RuntimeException('Could not reach answers');
    }

    private function processNsCandidates(Message $message): array
    {
        $candidates = [];
        /** @var NS $ns */
        foreach ($message->getRecordsByType(NS::getId()) as $ns) {
            $candidates[$ns->domain] = null;
        }

        /** @var A $a */
        foreach ($message->getRecordsByType(A::getId()) as $a) {
            $candidates[$a->name] = $a->ip->toString();
        }

        return array_filter($candidates);
    }

    private function queryByNsCandidates(string $domain, int $typeId, array $candidates): Message
    {
        foreach ($candidates as $ip) {
            try {
                $message = $this->client->by($ip)->query($domain, $typeId);
            } catch (RuntimeException) {
                continue;
            }

            return $message;
        }

        throw new RuntimeException('Neither of the candidates could give a response');
    }
}
