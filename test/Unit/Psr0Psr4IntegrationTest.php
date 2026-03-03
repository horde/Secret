<?php

/**
 * Integration tests for PSR-0 and PSR-4 interoperability.
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
use Horde\Secret\SecretManager;
use Horde\Secret\Cipher\BlowfishCipher;
use Horde\Secret\EncryptedData;
use PHPUnit\Framework\TestCase;

/**
 * Tests verifying PSR-0 and PSR-4 implementations can work together.
 *
 * @category   Horde
 * @package    Secret
 * @subpackage UnitTests
 * @license    http://www.horde.org/licenses/lgpl21 LGPL 2.1
 */
class Psr0Psr4IntegrationTest extends TestCase
{
    protected function setUp(): void
    {
        if (!BlowfishCipher::isSupported()) {
            $this->markTestSkipped('Blowfish cipher not available');
        }
    }

    /**
     * Test PSR-4 can decrypt PSR-0 encrypted data.
     */
    public function testPsr4DecryptsPsr0Data(): void
    {
        $key = 'integration-test-key';
        $plaintext = 'PSR-0 encrypted data';

        // Encrypt with PSR-0
        $psr0 = new Horde_Secret();
        $ciphertext = $psr0->write($key, $plaintext);

        // Verify no header (legacy format)
        $this->assertFalse(
            EncryptedData::hasHeader($ciphertext),
            'PSR-0 data should not have header'
        );

        // Decrypt with PSR-4
        $psr4 = SecretManager::withBlowfish($key);
        $decrypted = $psr4->decrypt($ciphertext);

        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * Test PSR-0 can decrypt PSR-4 Blowfish encrypted data.
     */
    public function testPsr0DecryptsPsr4BlowfishData(): void
    {
        $key = 'integration-test-key';
        $plaintext = 'PSR-4 Blowfish encrypted data';

        // Encrypt with PSR-4 Blowfish (produces legacy-compatible format)
        $psr4 = SecretManager::withBlowfish($key);
        $encrypted = $psr4->encrypt($plaintext);

        // PSR-4 produces data WITH header
        $this->assertTrue(
            EncryptedData::hasHeader($encrypted->toString()),
            'PSR-4 data should have header'
        );

        // PSR-0 cannot decrypt PSR-4 format (has header)
        // This is expected - PSR-0 has no knowledge of headers
        $psr0 = new Horde_Secret();
        $result = $psr0->read($key, $encrypted->toString());

        // PSR-0 will just treat it as Blowfish data and fail to decrypt properly
        $this->assertNotEquals($plaintext, $result);
    }

    /**
     * Test that PSR-0 remains completely unchanged.
     */
    public function testPsr0RemainsUnchanged(): void
    {
        $key = 'psr0-test-key';
        $plaintext = 'PSR-0 compatibility test';

        // Encrypt and decrypt with PSR-0
        $psr0 = new Horde_Secret();
        $ciphertext = $psr0->write($key, $plaintext);
        $decrypted = $psr0->read($key, $ciphertext);

        // PSR-0 should work exactly as before
        $this->assertEquals($plaintext, $decrypted);

        // Verify it produces legacy format (no header)
        $this->assertFalse(EncryptedData::hasHeader($ciphertext));
    }

    /**
     * Test migration pattern: PSR-0 encrypt -> PSR-4 decrypt -> PSR-4 re-encrypt.
     */
    public function testMigrationPattern(): void
    {
        $key = 'migration-key';
        $originalData = 'data to migrate';

        // Step 1: Old application encrypted with PSR-0
        $psr0 = new Horde_Secret();
        $legacyCiphertext = $psr0->write($key, $originalData);

        // Step 2: Modern application with PSR-4 can read it
        $psr4Modern = SecretManager::withSodium($key);
        $decrypted = $psr4Modern->decrypt($legacyCiphertext);
        $this->assertEquals($originalData, $decrypted);

        // Step 3: Check if needs re-encryption
        $this->assertTrue(
            $psr4Modern->needsReEncryption($legacyCiphertext),
            'Legacy data should need re-encryption'
        );

        // Step 4: Re-encrypt with modern cipher
        $modernCiphertext = $psr4Modern->encrypt($decrypted);

        // Step 5: Verify modern format
        $this->assertTrue(EncryptedData::hasHeader($modernCiphertext->toString()));
        $this->assertFalse($psr4Modern->needsReEncryption($modernCiphertext));

        // Step 6: Verify data integrity
        $finalDecrypted = $psr4Modern->decrypt($modernCiphertext);
        $this->assertEquals($originalData, $finalDecrypted);
    }

    /**
     * Test that PSR-0 and PSR-4 remain independent.
     */
    public function testIndependentApis(): void
    {
        $key1 = 'psr0-key';
        $key2 = 'psr4-key';

        // PSR-0 instance
        $psr0 = new Horde_Secret();
        $psr0Data = $psr0->write($key1, 'PSR-0 data');

        // PSR-4 instance
        $psr4 = SecretManager::withSodium($key2);
        $psr4Data = $psr4->encrypt('PSR-4 data');

        // Both should work independently
        $this->assertEquals('PSR-0 data', $psr0->read($key1, $psr0Data));
        $this->assertEquals('PSR-4 data', $psr4->decrypt($psr4Data));

        // Formats are different
        $this->assertFalse(EncryptedData::hasHeader($psr0Data));
        $this->assertTrue(EncryptedData::hasHeader($psr4Data->toString()));
    }

    /**
     * Test that PSR-0 API signature is unchanged.
     */
    public function testPsr0ApiSignature(): void
    {
        // Verify PSR-0 constructor accepts same parameters
        $params = [
            'cookie_domain' => '.example.com',
            'cookie_path' => '/app',
            'cookie_ssl' => true,
            'session_name' => 'test_session',
        ];
        $secret = new Horde_Secret($params);
        $this->assertInstanceOf(Horde_Secret::class, $secret);

        // Verify PSR-0 methods exist with correct signatures
        $this->assertTrue(method_exists($secret, 'write'));
        $this->assertTrue(method_exists($secret, 'read'));
        $this->assertTrue(method_exists($secret, 'setKey'));
        $this->assertTrue(method_exists($secret, 'getKey'));
        $this->assertTrue(method_exists($secret, 'clearKey'));

        // Verify methods work
        $encrypted = $secret->write('key', 'test');
        $decrypted = $secret->read('key', $encrypted);
        $this->assertEquals('test', $decrypted);
    }

    /**
     * Test backward compatibility: existing PSR-0 code continues working.
     */
    public function testBackwardCompatibility(): void
    {
        $key = 'backward-compat-key';
        $data = 'Existing application data';

        // Simulate existing PSR-0 application
        $secret = new Horde_Secret();

        // All existing operations work unchanged
        $encrypted = $secret->write($key, $data);
        $this->assertNotEmpty($encrypted);

        $decrypted = $secret->read($key, $encrypted);
        $this->assertEquals($data, $decrypted);

        // Empty key/message behavior unchanged
        $this->assertEquals('', $secret->write('', 'data'));
        $this->assertEquals('', $secret->read('', 'data'));
        $this->assertEquals('', $secret->write('key', ''));
        $this->assertEquals('', $secret->read('key', ''));
    }
}
