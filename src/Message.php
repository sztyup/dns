<?php

declare(strict_types=1);

namespace Sztyup\Dns;

use RuntimeException;
use Sztyup\Dns\DNSSEC\SignedSet;
use Sztyup\Dns\RecordTypes\OPT;
use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\RecordTypes\RRSIG;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

use function count;

class Message implements HasWireFormat
{
    public int $id;

    public int $opcode;

    public int $qr;

    public bool $authoritative = false;

    public bool $truncated = false;

    public bool $recursionRequest = false;

    public bool $recursionAvailable = false;

    public bool $authentic = false;

    public bool $disableAuth = false;

    public int $errorCode = 0;

    /** @var Question[] */
    public array $questions = [];

    /** @var ResourceRecord[] */
    public array $answers = [];

    /** @var ResourceRecord[] */
    public array $nameServerRecords = [];

    /** @var ResourceRecord[] */
    public array $additionalRecords = [];

    public static function fromWireFormat(StringStream $stream, int $length): Message
    {
        $message = new self();

        $message->id = $stream->readUInt16();

        $flags = $stream->readUInt16();

        if ($flags & DnsConstants::QR_RESPONSE === 0) {
            throw new RuntimeException('Response arrived with query QR type');
        }

        $qdcount = $stream->readUInt16();
        $ancount = $stream->readUInt16();
        $nscount = $stream->readUInt16();
        $arcount = $stream->readUInt16();

        $message->authoritative      = (bool)($flags & DnsConstants::FLAG_AUTHORITATIVE);
        $message->truncated          = (bool)($flags & DnsConstants::FLAG_TRUNCATED);
        $message->recursionRequest   = (bool)($flags & DnsConstants::FLAG_RECURSION_DESIRED);
        $message->recursionAvailable = (bool)($flags & DnsConstants::FLAG_RECURSION_AVAILABLE);
        $message->authentic          = (bool)($flags & DnsConstants::FLAG_AUTHENTIC_DATA);
        $message->disableAuth        = (bool)($flags & DnsConstants::FLAG_CHECKING_DISABLED);

        $message->errorCode = $flags & DnsConstants::RCODE_MASK;


        for ($i = 0; $i < $qdcount; $i++) {
            $message->questions[] = Question::fromWireFormat($stream, $length);
        }

        for ($i = 0; $i < $ancount; $i++) {
            $message->answers[] = ResourceRecord::fromWireFormat($stream, $length);
        }

        for ($i = 0; $i < $nscount; $i++) {
            $message->nameServerRecords[] = ResourceRecord::fromWireFormat($stream, $length);
        }

        for ($i = 0; $i < $arcount; $i++) {
            $message->additionalRecords[] = ResourceRecord::fromWireFormat($stream, $length);
        }

        if (!$stream->eof()) {
            throw new RuntimeException('Data skipped at the end of message');
        }

        $message->postProcessing();

        return $message;
    }

    public function toWireFormat(): BinaryString
    {
        $query = new BinaryString();

        $query->writeUInt16(random_int(0, 2 ** 14)); // ID

        $flags = 0;

        if ($this->qr === 0) {
            $flags |= DnsConstants::QR_QUERY;
        } else {
            $flags |= DnsConstants::QR_RESPONSE;
        }

        $flags |= DnsConstants::OPCODES[$this->opcode];

        if ($this->authoritative) {
            $flags |= DnsConstants::FLAG_AUTHORITATIVE;
        }

        if ($this->truncated) {
            $flags |= DnsConstants::FLAG_TRUNCATED;
        }

        if ($this->recursionRequest) {
            $flags |= DnsConstants::FLAG_RECURSION_DESIRED;
        }

        if ($this->recursionAvailable) {
            $flags |= DnsConstants::FLAG_RECURSION_AVAILABLE;
        }

        if ($this->authentic) {
            $flags |= DnsConstants::FLAG_AUTHENTIC_DATA;
        }

        if ($this->disableAuth) {
            $flags |= DnsConstants::FLAG_CHECKING_DISABLED;
        }

        // QR, Opcode, AA, TC, RD, RA, Z, RCODE
        $query->writeUInt16($flags);

        $query->writeUInt16(count($this->questions)); // QDCOUNT
        $query->writeUInt16(count($this->answers)); // ANCOUNT
        $query->writeUInt16(count($this->nameServerRecords)); // NSCOUNT
        $query->writeUInt16(count($this->additionalRecords)); // ARCOUNT

        foreach ($this->questions as $question) {
            $query->append($question->toWireFormat());
        }

        foreach ($this->answers as $answer) {
            $query->append($answer->toWireFormat());
        }

        foreach ($this->nameServerRecords as $nsRecord) {
            $query->append($nsRecord->toWireFormat());
        }

        foreach ($this->additionalRecords as $arRecord) {
            $query->append($arRecord->toWireFormat());
        }

        return $query;
    }

    public function getRecordsByType(int $type): array
    {
        $result = [];
        foreach ($this->answers as $answer) {
            if ($answer::getId() === $type) {
                $result[] = $answer;
            }
        }

        foreach ($this->nameServerRecords as $nsRecord) {
            if ($nsRecord::getId() === $type) {
                $result[] = $nsRecord;
            }
        }

        foreach ($this->additionalRecords as $arRecord) {
            if ($arRecord::getId() === $type) {
                $result[] = $arRecord;
            }
        }

        return $result;
    }

    /**
     * @return SignedSet[]
     */
    public function findSignedSets(): array
    {
        $sets = [];

        /** @var RRSIG $rrsig */
        foreach ($this->getRecordsByType(RRSIG::getId()) as $rrsig) {
            $name = DnsConstants::RECORD_TYPES[$rrsig->typeCovered]::getName();
            $sets[$name] = new SignedSet($this->getRecordsByType($rrsig->typeCovered), $rrsig);
        }

        return $sets;
    }

    public function hasError(): bool
    {
        return $this->errorCode !== 0;
    }

    private function postProcessing(): void
    {
        foreach ($this->additionalRecords as $additionalRecord) {
            if ($additionalRecord instanceof OPT && $additionalRecord->extendedErrorCode > 0) {
                $this->errorCode <<= 8;
                $this->errorCode += $additionalRecord->extendedErrorCode;
            }
        }
    }
}
