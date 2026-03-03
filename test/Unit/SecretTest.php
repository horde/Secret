<?php

/**
 * Test the secret encryption class.
 *
 * Copyright 2009-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category   Horde
 * @package    Secret
 * @subpackage UnitTests
 * @author     Michael Slusarz <slusarz@horde.org>
 * @license    http://www.horde.org/licenses/lgpl21 LGPL 2.1
 */

declare(strict_types=1);

namespace Horde\Secret\Test\Unit;

use Horde_Secret;
use Horde_Secret_Exception;
use Horde\Secret\Test\Mock\StringableObject;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Test the secret encryption class.
 *
 * @category   Horde
 * @package    Secret
 * @subpackage UnitTests
 * @author     Michael Slusarz <slusarz@horde.org>
 * @license    http://www.horde.org/licenses/lgpl21 LGPL 2.1
 */
#[CoversClass(Horde_Secret::class)]
#[Group('horde_secret')]
class SecretTest extends TestCase
{
    /**
     * Test encryption/decryption with 8-bit key
     */
    public function test8BitKey(): void
    {
        $secret = new Horde_Secret();

        $key = "\x88";
        $plaintext = "\x01\x01\x01\x01\x01\x01\x01\x01";

        $encrypted = $secret->write($key, $plaintext);
        $decrypted = $secret->read($key, $encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * Test encryption/decryption with 64-bit key
     */
    public function test64BitKey(): void
    {
        $secret = new Horde_Secret();

        $key = "\x00\x00\x00\x00\x00\x00\x00\x00";
        $plaintext = "\x01\x01\x01\x01\x01\x01\x01\x01";

        $encrypted = $secret->write($key, $plaintext);
        $decrypted = $secret->read($key, $encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * Test encryption/decryption with 128-bit key
     */
    public function test128BitKey(): void
    {
        $secret = new Horde_Secret();

        $key = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        $plaintext = "\x01\x01\x01\x01\x01\x01\x01\x01";

        $encrypted = $secret->write($key, $plaintext);
        $decrypted = $secret->read($key, $encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * Bug #9121: Remove null padding on stored data
     */
    public function testNullPadding(): void
    {
        $secret = new Horde_Secret();

        $key = "\x88";
        $plaintext = "\x01\x01\x01\x01\x01\x01\x01\x01";

        $encrypted = $secret->write($key, $plaintext);
        $decrypted = $secret->read($key, $encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * Test that non-string keys throw exception
     */
    public function testKeyException(): void
    {
        $this->expectException(Horde_Secret_Exception::class);

        $secret = new Horde_Secret();
        $secret->read(new StringableObject(), "\x01");
    }

    /**
     * Test that keys longer than 56 bytes are truncated
     */
    public function testLongKeyTruncation(): void
    {
        $secret = new Horde_Secret();

        // Keys longer than 56 bytes should be truncated to 56
        $key1 = '012345678901234567890123456789012345678901234567890123456';     // 57 chars
        $key2 = '012345678901234567890123456789012345678901234567890123456789'; // 59 chars

        $plaintext = "\x01";

        // Both should produce same result (truncated to 56 bytes)
        $encrypted1 = $secret->read($key1, $plaintext);
        $encrypted2 = $secret->read($key2, $plaintext);

        $this->assertEquals($encrypted1, $encrypted2);
    }

    /**
     * Test reading with empty key returns empty string
     */
    public function testShortKeyRead(): void
    {
        $secret = new Horde_Secret();
        $result = $secret->read('', "\x01");

        $this->assertEquals('', $result);
    }

    /**
     * Test writing with empty key returns empty string
     */
    public function testShortKeyWrite(): void
    {
        $secret = new Horde_Secret();
        $result = $secret->write('', "\x01");

        $this->assertEquals('', $result);
    }

    /**
     * Test round-trip encryption with various data types
     */
    public function testRoundTripEncryption(): void
    {
        $secret = new Horde_Secret();
        $key = 'test-key-12345';

        $testData = [
            'simple string',
            'String with special chars: !@#$%^&*()',
            'Unicode: 你好世界 🚀',
            '12345',
            'Binary: ' . "\x00\x01\x02\x03",
        ];

        foreach ($testData as $plaintext) {
            $encrypted = $secret->write($key, $plaintext);
            $decrypted = $secret->read($key, $encrypted);

            $this->assertEquals(
                $plaintext,
                $decrypted,
                "Round-trip failed for: " . bin2hex($plaintext)
            );
        }
    }

    /**
     * Test that different keys produce different ciphertext
     */
    public function testDifferentKeysDifferentCiphertext(): void
    {
        $secret = new Horde_Secret();
        $plaintext = 'test data';

        $key1 = 'key1';
        $key2 = 'key2';

        $encrypted1 = $secret->write($key1, $plaintext);
        $encrypted2 = $secret->write($key2, $plaintext);

        $this->assertNotEquals(
            $encrypted1,
            $encrypted2,
            'Different keys should produce different ciphertext'
        );
    }

    /**
     * Test cookie configuration parameters
     */
    public function testCookieConfiguration(): void
    {
        $params = [
            'cookie_domain' => '.example.com',
            'cookie_path' => '/app',
            'cookie_ssl' => true,
            'session_name' => 'test_session',
        ];

        $secret = new Horde_Secret($params);

        // Just verify construction succeeds with parameters
        $this->assertInstanceOf(Horde_Secret::class, $secret);
    }
}
