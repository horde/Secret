<?php

/**
 * Tests for AesGcmCipher.
 *
 * Copyright 2009-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category   Horde
 * @package    Secret
 * @subpackage UnitTests
 * @license    http://www.horde.org/licenses/lgpl21 LGPL 2.1
 */

declare(strict_types=1);

namespace Horde\Secret\Test\Unit\Cipher;

use Horde\Secret\Cipher\AesGcmCipher;
use Horde\Secret\Exception\EncryptionException;
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\InvalidKeyException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

#[CoversClass(AesGcmCipher::class)]
#[RequiresPhpExtension('openssl')]
class AesGcmCipherTest extends TestCase
{
    private string $key;

    protected function setUp(): void
    {
        if (!AesGcmCipher::isSupported()) {
            $this->markTestSkipped('AES-GCM not supported');
        }

        $this->key = AesGcmCipher::generateKey();
    }

    public function testIsSupportedReturnsTrue(): void
    {
        $this->assertTrue(AesGcmCipher::isSupported());
    }

    public function testConstructorAcceptsValidKey(): void
    {
        $cipher = new AesGcmCipher($this->key);

        $this->assertInstanceOf(AesGcmCipher::class, $cipher);
        $this->assertEquals(0x03, $cipher->getVersion());
        $this->assertEquals('AES-256-GCM', $cipher->getName());
    }

    public function testConstructorRejectsInvalidKeyLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('must be exactly 32 bytes');

        new AesGcmCipher('wrong-length-key');
    }

    public function testEncryptAndDecryptRoundTrip(): void
    {
        $cipher = new AesGcmCipher($this->key);
        $plaintext = 'secret message';

        $ciphertext = $cipher->encrypt($plaintext);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptRejectsEmptyPlaintext(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Cannot encrypt empty plaintext');

        $cipher = new AesGcmCipher($this->key);
        $cipher->encrypt('');
    }

    public function testDecryptWithWrongKeyFails(): void
    {
        $this->expectException(DecryptionException::class);

        $cipher1 = new AesGcmCipher($this->key);
        $ciphertext = $cipher1->encrypt('secret');

        $wrongKey = AesGcmCipher::generateKey();
        $cipher2 = new AesGcmCipher($wrongKey);
        $cipher2->decrypt($ciphertext);
    }

    public function testDecryptWithTamperedDataFails(): void
    {
        $this->expectException(DecryptionException::class);

        $cipher = new AesGcmCipher($this->key);
        $ciphertext = $cipher->encrypt('secret');

        // Tamper with the last byte (part of auth tag)
        $tampered = $ciphertext;
        $lastPos = strlen($tampered) - 1;
        $tampered[$lastPos] = chr(ord($tampered[$lastPos]) ^ 0xFF);

        $cipher->decrypt($tampered);
    }

    public function testDecryptRejectsTooShortCiphertext(): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('too short');

        $cipher = new AesGcmCipher($this->key);
        $cipher->decrypt('short');
    }

    public function testEncryptProducesDifferentCiphertextEachTime(): void
    {
        $cipher = new AesGcmCipher($this->key);
        $plaintext = 'same message';

        $ciphertext1 = $cipher->encrypt($plaintext);
        $ciphertext2 = $cipher->encrypt($plaintext);

        // Different random nonces produce different ciphertexts
        $this->assertNotEquals($ciphertext1, $ciphertext2);
    }

    public function testGetNonceLength(): void
    {
        $cipher = new AesGcmCipher($this->key);

        $this->assertEquals(12, $cipher->getNonceLength());
    }

    public function testGetTagLength(): void
    {
        $cipher = new AesGcmCipher($this->key);

        $this->assertEquals(16, $cipher->getTagLength());
    }

    public function testCiphertextStructure(): void
    {
        $cipher = new AesGcmCipher($this->key);
        $plaintext = 'test';

        $ciphertext = $cipher->encrypt($plaintext);

        // Ciphertext = nonce (12) + encrypted data (4) + tag (16)
        $expectedLength = 12 + 4 + 16;
        $this->assertEquals($expectedLength, strlen($ciphertext));
    }

    public function testRoundTripWithBinaryData(): void
    {
        $cipher = new AesGcmCipher($this->key);
        $binary = "\x00\x01\x02\xFF\xFE\xFD";

        $ciphertext = $cipher->encrypt($binary);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($binary, $decrypted);
    }

    public function testRoundTripWithUnicode(): void
    {
        $cipher = new AesGcmCipher($this->key);
        $unicode = '你好世界 🚀 مرحبا بالعالم';

        $ciphertext = $cipher->encrypt($unicode);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($unicode, $decrypted);
    }

    public function testRoundTripWithLargeData(): void
    {
        $cipher = new AesGcmCipher($this->key);
        $large = str_repeat('A', 100000);

        $ciphertext = $cipher->encrypt($large);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($large, $decrypted);
    }

    public function testGenerateKeyCreatesValidKey(): void
    {
        $key = AesGcmCipher::generateKey();

        $this->assertEquals(32, strlen($key));

        // Should work with cipher
        $cipher = new AesGcmCipher($key);
        $this->assertInstanceOf(AesGcmCipher::class, $cipher);
    }

    public function testGenerateKeyCreatesUniqueKeys(): void
    {
        $key1 = AesGcmCipher::generateKey();
        $key2 = AesGcmCipher::generateKey();

        $this->assertNotEquals($key1, $key2);
    }
}
