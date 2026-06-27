<?php

/**
 * Tests for SecretManager facade including migration scenarios.
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

namespace Horde\Secret\Test\Unit;

use Horde_Secret;
use Horde\Secret\Cipher\SodiumCipher;
use Horde\Secret\Cipher\AesGcmCipher;
use Horde\Secret\Cipher\BlowfishCipher;
use Horde\Secret\EncryptedData;
use Horde\Secret\SecretManager;
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\UnsupportedCipherException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ValueError;

#[CoversClass(SecretManager::class)]
class SecretManagerTest extends TestCase
{
    private string $key;

    protected function setUp(): void
    {
        $this->key = random_bytes(32);
    }

    public function testCreateWithAutoSelection(): void
    {
        $secret = SecretManager::create($this->key);

        $this->assertInstanceOf(SecretManager::class, $secret);

        // Should prefer Sodium if available
        if (SodiumCipher::isSupported()) {
            $this->assertEquals('XSalsa20-Poly1305', $secret->getCipherName());
            $this->assertEquals(0x02, $secret->getCipherVersion());
        } elseif (AesGcmCipher::isSupported()) {
            $this->assertEquals('AES-256-GCM', $secret->getCipherName());
            $this->assertEquals(0x03, $secret->getCipherVersion());
        }
    }

    public function testWithSodium(): void
    {
        if (!SodiumCipher::isSupported()) {
            $this->markTestSkipped('Sodium not available');
        }

        $secret = SecretManager::withSodium($this->key);

        $this->assertEquals('XSalsa20-Poly1305', $secret->getCipherName());
        $this->assertEquals(0x02, $secret->getCipherVersion());
    }

    public function testWithAesGcm(): void
    {
        if (!AesGcmCipher::isSupported()) {
            $this->markTestSkipped('AES-GCM not available');
        }

        $secret = SecretManager::withAesGcm($this->key);

        $this->assertEquals('AES-256-GCM', $secret->getCipherName());
        $this->assertEquals(0x03, $secret->getCipherVersion());
    }

    public function testWithBlowfish(): void
    {
        if (!BlowfishCipher::isSupported()) {
            $this->markTestSkipped('Blowfish not available');
        }

        $secret = SecretManager::withBlowfish($this->key);

        $this->assertEquals('Blowfish-ECB', $secret->getCipherName());
        $this->assertEquals(0x01, $secret->getCipherVersion());
    }

    public function testEncryptReturnsEncryptedData(): void
    {
        $secret = SecretManager::create($this->key);
        $plaintext = 'secret message';

        $encrypted = $secret->encrypt($plaintext);

        $this->assertInstanceOf(EncryptedData::class, $encrypted);
        $this->assertNotEquals($plaintext, $encrypted->toString());
    }

    public function testEncryptIncludesMagicHeader(): void
    {
        $secret = SecretManager::create($this->key);
        $encrypted = $secret->encrypt('test');

        $data = $encrypted->toString();
        $this->assertStringStartsWith('HS', $data);
    }

    public function testDecryptWithEncryptedDataObject(): void
    {
        $secret = SecretManager::create($this->key);
        $plaintext = 'secret message';

        $encrypted = $secret->encrypt($plaintext);
        $decrypted = $secret->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testDecryptWithString(): void
    {
        $secret = SecretManager::create($this->key);
        $plaintext = 'secret message';

        $encrypted = $secret->encrypt($plaintext);
        $decrypted = $secret->decrypt($encrypted->toString());

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testRoundTripEncryption(): void
    {
        $secret = SecretManager::create($this->key);

        $testCases = [
            'simple text',
            'Unicode: 你好世界 🚀',
            'Binary: ' . "\x00\x01\x02\xFF",
            'Long: ' . str_repeat('x', 10000),
        ];

        foreach ($testCases as $plaintext) {
            $encrypted = $secret->encrypt($plaintext);
            $decrypted = $secret->decrypt($encrypted);

            $this->assertEquals($plaintext, $decrypted);
        }
    }

    public function testDecryptLegacyBlowfishData(): void
    {
        if (!BlowfishCipher::isSupported()) {
            $this->markTestSkipped('Blowfish not available');
        }

        $key = 'test-key-12345';

        // Create legacy PSR-0 encrypted data (no header)
        $legacySecret = new Horde_Secret();
        $legacyCiphertext = $legacySecret->write($key, 'legacy data');

        // Decrypt with modern PSR-4
        $modernSecret = SecretManager::create($key);
        $decrypted = $modernSecret->decrypt($legacyCiphertext);

        $this->assertEquals('legacy data', $decrypted);
    }

    public function testNeedsReEncryptionDetectsLegacyFormat(): void
    {
        if (!BlowfishCipher::isSupported()) {
            $this->markTestSkipped('Blowfish not available');
        }

        $key = 'test-key';

        // Legacy data (no header)
        $legacySecret = new Horde_Secret();
        $legacyCiphertext = $legacySecret->write($key, 'data');

        $modernSecret = SecretManager::create($key);

        // Should detect legacy format needs upgrade
        $this->assertTrue($modernSecret->needsReEncryption($legacyCiphertext));
    }

    public function testNeedsReEncryptionDetectsModernFormat(): void
    {
        $secret = SecretManager::create($this->key);
        $encrypted = $secret->encrypt('data');

        // Modern format with current cipher - no re-encryption needed
        $this->assertFalse($secret->needsReEncryption($encrypted));
    }

    public function testNeedsReEncryptionDetectsDifferentCipher(): void
    {
        if (!SodiumCipher::isSupported() || !AesGcmCipher::isSupported()) {
            $this->markTestSkipped('Need both Sodium and AES-GCM');
        }

        // Encrypt with Sodium
        $sodiumSecret = SecretManager::withSodium($this->key);
        $encrypted = $sodiumSecret->encrypt('data');

        // Check with AES-GCM manager
        $aesSecret = SecretManager::withAesGcm($this->key);

        // Should detect different cipher version
        $this->assertTrue($aesSecret->needsReEncryption($encrypted));
    }

    public function testMigrationScenarioLegacyToModern(): void
    {
        if (!BlowfishCipher::isSupported() || !SodiumCipher::isSupported()) {
            $this->markTestSkipped('Need Blowfish and Sodium');
        }

        $key = 'migration-test-key';
        $originalData = 'data to migrate';

        // Step 1: Old system encrypts with Blowfish (PSR-0)
        $legacySecret = new Horde_Secret();
        $legacyCiphertext = $legacySecret->write($key, $originalData);

        // Step 2: Check if legacy format (no header)
        $this->assertFalse(EncryptedData::hasHeader($legacyCiphertext));

        // Step 3: Modern system decrypts legacy data
        $modernSecret = SecretManager::withSodium($key);
        $decrypted = $modernSecret->decrypt($legacyCiphertext);
        $this->assertEquals($originalData, $decrypted);

        // Step 4: Check if needs re-encryption
        $this->assertTrue($modernSecret->needsReEncryption($legacyCiphertext));

        // Step 5: Re-encrypt with modern cipher
        $modernCiphertext = $modernSecret->encrypt($decrypted);

        // Step 6: Verify new format has header
        $this->assertTrue(EncryptedData::hasHeader($modernCiphertext->toString()));

        // Step 7: Verify no longer needs re-encryption
        $this->assertFalse($modernSecret->needsReEncryption($modernCiphertext));

        // Step 8: Verify decryption still works
        $finalDecrypted = $modernSecret->decrypt($modernCiphertext);
        $this->assertEquals($originalData, $finalDecrypted);
    }

    public function testMigrationScenarioCrossAlgorithm(): void
    {
        if (!SodiumCipher::isSupported() || !AesGcmCipher::isSupported()) {
            $this->markTestSkipped('Need both Sodium and AES-GCM');
        }

        $data = 'cross-algorithm migration';

        // Encrypt with AES-GCM
        $aesSecret = SecretManager::withAesGcm($this->key);
        $aesCiphertext = $aesSecret->encrypt($data);

        // Decrypt with Sodium manager (should work - automatic detection)
        $sodiumSecret = SecretManager::withSodium($this->key);
        $decrypted = $sodiumSecret->decrypt($aesCiphertext);

        $this->assertEquals($data, $decrypted);

        // Check if needs re-encryption to Sodium
        $this->assertTrue($sodiumSecret->needsReEncryption($aesCiphertext));

        // Re-encrypt with Sodium
        $sodiumCiphertext = $sodiumSecret->encrypt($decrypted);

        // Verify version changed
        $this->assertEquals(0x03, $aesCiphertext->getVersion());  // AES-GCM
        $this->assertEquals(0x02, $sodiumCiphertext->getVersion()); // Sodium

        // No longer needs re-encryption
        $this->assertFalse($sodiumSecret->needsReEncryption($sodiumCiphertext));
    }

    public function testDecryptWithWrongKeyFails(): void
    {
        $this->expectException(DecryptionException::class);

        $secret1 = SecretManager::create($this->key);
        $encrypted = $secret1->encrypt('secret');

        $wrongKey = random_bytes(32);
        $secret2 = SecretManager::create($wrongKey);
        $secret2->decrypt($encrypted);
    }

    public function testDecryptInvalidFormatFails(): void
    {
        $secret = SecretManager::create($this->key);

        // Test with data too short for any cipher
        try {
            $secret->decrypt('short');
            $this->fail('Should have thrown DecryptionException for short data');
        } catch (DecryptionException $e) {
            $this->addToAssertionCount(1);
        }

        // Test with invalid header format (unknown cipher version)
        try {
            $encrypted = EncryptedData::fromString('HSXinvalid');
            $secret->decrypt($encrypted);
            $this->fail('Should have thrown exception for unknown cipher version');
        } catch (UnsupportedCipherException $e) {
            $this->addToAssertionCount(1);
        }

        // NOTE: We cannot test "random valid-length data" because Blowfish
        // will decrypt it (to garbage). This is expected behavior for legacy support.
    }

    public function testBatchMigrationSimulation(): void
    {
        if (!BlowfishCipher::isSupported() || !SodiumCipher::isSupported()) {
            $this->markTestSkipped('Need Blowfish and Sodium');
        }

        $key = 'batch-migration-key';

        // Simulate database with old encrypted records
        $legacyRecords = [
            'record1' => 'sensitive data 1',
            'record2' => 'sensitive data 2',
            'record3' => 'sensitive data 3',
        ];

        // Encrypt all with legacy system
        $legacySecret = new Horde_Secret();
        $encryptedRecords = [];
        foreach ($legacyRecords as $id => $data) {
            $encryptedRecords[$id] = $legacySecret->write($key, $data);
        }

        // Migrate all to modern system
        $modernSecret = SecretManager::withSodium($key);
        $migratedRecords = [];

        foreach ($encryptedRecords as $id => $ciphertext) {
            // Decrypt legacy
            $decrypted = $modernSecret->decrypt($ciphertext);

            // Re-encrypt with modern cipher
            $migratedRecords[$id] = $modernSecret->encrypt($decrypted);
        }

        // Verify all migrated correctly
        foreach ($legacyRecords as $id => $originalData) {
            $decrypted = $modernSecret->decrypt($migratedRecords[$id]);
            $this->assertEquals($originalData, $decrypted);

            // Verify modern format
            $this->assertTrue(EncryptedData::hasHeader($migratedRecords[$id]->toString()));
            $this->assertFalse($modernSecret->needsReEncryption($migratedRecords[$id]));
        }
    }

    public function testLazyMigrationPattern(): void
    {
        if (!BlowfishCipher::isSupported() || !SodiumCipher::isSupported()) {
            $this->markTestSkipped('Need Blowfish and Sodium');
        }

        $key = 'lazy-migration-key';

        // Old encrypted data
        $legacySecret = new Horde_Secret();
        $oldCiphertext = $legacySecret->write($key, 'old data');

        // Modern system with lazy migration
        $modernSecret = SecretManager::withSodium($key);

        // On read, decrypt old format
        $decrypted = $modernSecret->decrypt($oldCiphertext);
        $this->assertEquals('old data', $decrypted);

        // Check if needs migration
        if ($modernSecret->needsReEncryption($oldCiphertext)) {
            // Re-encrypt on write
            $newCiphertext = $modernSecret->encrypt($decrypted);

            // Verify migration successful
            $this->assertFalse($modernSecret->needsReEncryption($newCiphertext));

            // Verify data integrity
            $finalDecrypted = $modernSecret->decrypt($newCiphertext);
            $this->assertEquals('old data', $finalDecrypted);
        }
    }

    public function testDeriveKeyIsDeterministic(): void
    {
        // Same input key must produce identical SecretManager behavior
        $key = 'deterministic-test-key';

        $secret1 = SecretManager::create($key);
        $secret2 = SecretManager::create($key);

        $encrypted = $secret1->encrypt('test data');
        $decrypted = $secret2->decrypt($encrypted);

        $this->assertEquals('test data', $decrypted);
    }

    public function testDeriveKeyWithEmptyKeyThrows(): void
    {
        // hash_hkdf rejects empty key input
        $this->expectException(ValueError::class);
        SecretManager::create('');
    }

    public function testDecryptLegacyTooShortThrows(): void
    {
        $secret = SecretManager::create($this->key);

        // 7 bytes: below the 8-byte minimum for legacy Blowfish
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('too short');
        $secret->decrypt(str_repeat('x', 7));
    }

    public function testDecryptLegacyExactlyEightBytes(): void
    {
        if (!BlowfishCipher::isSupported()) {
            $this->markTestSkipped('Blowfish not available');
        }

        $key = 'test-key';
        $secret = SecretManager::create($key);

        // Encrypt a short message with legacy PSR-0 to get valid 8-byte+ ciphertext
        $legacySecret = new Horde_Secret();
        $ciphertext = $legacySecret->write($key, 'abcdefgh');

        // Should not throw — valid Blowfish block
        $decrypted = $secret->decrypt($ciphertext);
        $this->assertEquals('abcdefgh', $decrypted);
    }

    public function testDecryptUnknownCipherVersionThrows(): void
    {
        $secret = SecretManager::create($this->key);

        // Version 0x04 is not in CIPHER_REGISTRY
        $fakeData = new EncryptedData(0x04, str_repeat('x', 40));

        $this->expectException(UnsupportedCipherException::class);
        $this->expectExceptionMessage('Unknown cipher version: 0x04');
        $secret->decrypt($fakeData);
    }

    public function testNeedsReEncryptionWithEncryptedDataObject(): void
    {
        $secret = SecretManager::create($this->key);

        // Current cipher — no re-encryption needed
        $encrypted = $secret->encrypt('data');
        $this->assertFalse($secret->needsReEncryption($encrypted));
    }

    public function testNeedsReEncryptionWithEncryptedDataDifferentVersion(): void
    {
        if (!SodiumCipher::isSupported() || !AesGcmCipher::isSupported()) {
            $this->markTestSkipped('Need both Sodium and AES-GCM');
        }

        // Encrypt with AES-GCM, check with Sodium manager
        $aesSecret = SecretManager::withAesGcm($this->key);
        $encrypted = $aesSecret->encrypt('data');

        $sodiumSecret = SecretManager::withSodium($this->key);
        $this->assertTrue($sodiumSecret->needsReEncryption($encrypted));
    }

    public function testBlowfishKeyBypassesHkdf(): void
    {
        if (!BlowfishCipher::isSupported()) {
            $this->markTestSkipped('Blowfish not available');
        }

        $key = 'test-key-12345';

        // PSR-0 uses key directly with Blowfish
        $legacySecret = new Horde_Secret();
        $legacyCiphertext = $legacySecret->write($key, 'blowfish data');

        // SecretManager::withBlowfish must also use key directly (no HKDF)
        // so it can decrypt legacy data
        $manager = SecretManager::withBlowfish($key);
        $decrypted = $manager->decrypt($legacyCiphertext);

        $this->assertEquals('blowfish data', $decrypted);
    }

    public function testDecryptStringWithUnknownVersionInHeader(): void
    {
        $secret = SecretManager::create($this->key);

        // Manually craft string with HS header but unknown version 0xFF
        $fakeString = 'HS' . chr(0xFF) . str_repeat('x', 40);

        $this->expectException(UnsupportedCipherException::class);
        $secret->decrypt($fakeString);
    }
}
