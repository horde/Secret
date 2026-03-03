# Horde_Secret

Modern secret encryption library with authenticated encryption support.

[![Build Status](https://github.com/horde/Secret/workflows/CI/badge.svg)](https://github.com/horde/Secret/actions)

## Overview

Horde_Secret provides a dual-stack API for encrypting and decrypting small pieces of data:

- **PSR-4 Modern API** (`Horde\Secret\SecretManager`) - Authenticated encryption with Libsodium/AES-GCM
- **PSR-0 Legacy API** (`Horde_Secret`) - Backward-compatible Blowfish encryption

## Installation

```bash
composer require horde/secret
```

## Quick Start

### Modern API (Recommended for new projects)

```php
use Horde\Secret\SecretManager;

// Automatic cipher selection (prefers Sodium)
$secret = SecretManager::create($key);

// Encrypt
$encrypted = $secret->encrypt('sensitive data');

// Decrypt
$decrypted = $secret->decrypt($encrypted);
```

### Legacy API (Backward compatible)

```php
$secret = new Horde_Secret();

// Encrypt
$encrypted = $secret->write($key, 'sensitive data');

// Decrypt
$decrypted = $secret->read($key, $encrypted);
```

## Features

### Modern API (PSR-4)

✅ **Authenticated Encryption (AEAD)**
- Prevents tampering and forgery attacks
- Automatic integrity verification

✅ **Multiple Cipher Support**
- **Libsodium XSalsa20-Poly1305** (primary, version 0x02)
- **AES-256-GCM** (fallback, version 0x03)
- **Blowfish ECB** (legacy compatibility, version 0x01)

✅ **Type Safety**
- PHP 8.1+ strict types
- Immutable value objects
- Full type declarations

✅ **Automatic Legacy Detection**
- Decrypts old PSR-0 data seamlessly
- Migration helpers included

### Legacy API (PSR-0)

- 100% backward compatible with Horde_Secret 2.x
- No breaking changes
- Drop-in upgrade
- Cookie/session key management

## Usage Examples

### Cipher Selection

```php
use Horde\Secret\SecretManager;

// Automatic selection (recommended)
$secret = SecretManager::create($key);

// Explicit cipher selection
$sodium = SecretManager::withSodium($key);    // XSalsa20-Poly1305
$aes = SecretManager::withAesGcm($key);       // AES-256-GCM
$blowfish = SecretManager::withBlowfish($key); // Legacy only

// Check current cipher
echo $secret->getCipherName();     // "XSalsa20-Poly1305"
echo $secret->getCipherVersion();  // 0x02
```

### Working with Encrypted Data

```php
use Horde\Secret\SecretManager;

$secret = SecretManager::create($key);

// Encrypt returns an EncryptedData object
$encrypted = $secret->encrypt('my secret');

// Get Base64-encoded string for storage
$storedValue = $encrypted->toBase64();

// Decrypt from string or object
$decrypted = $secret->decrypt($storedValue);
```

### Migration from Legacy Format

```php
use Horde\Secret\SecretManager;

$secret = SecretManager::create($key);

// Decrypt legacy PSR-0 data (automatic detection)
$decrypted = $secret->decrypt($oldCiphertext);

// Check if needs re-encryption
if ($secret->needsReEncryption($oldCiphertext)) {
    // Upgrade to modern format
    $newCiphertext = $secret->encrypt($decrypted);

    // Update database
    $db->update('table', [
        'encrypted_field' => $newCiphertext->toString()
    ], ['id' => $recordId]);
}
```

### Lazy Migration Pattern

```php
use Horde\Secret\SecretManager;

function getData($key, $ciphertext, $db, $recordId) {
    $secret = SecretManager::create($key);

    // Decrypt (works with any format)
    $data = $secret->decrypt($ciphertext);

    // Opportunistically upgrade
    if ($secret->needsReEncryption($ciphertext)) {
        $newCiphertext = $secret->encrypt($data);
        $db->update('table', ['field' => $newCiphertext->toString()], ['id' => $recordId]);
    }

    return $data;
}
```

### Error Handling

```php
use Horde\Secret\SecretManager;
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\InvalidKeyException;
use Horde\Secret\Exception\UnsupportedCipherException;

try {
    $secret = SecretManager::create($key);
    $decrypted = $secret->decrypt($ciphertext);
} catch (DecryptionException $e) {
    // Wrong key or corrupted/tampered data
    error_log("Decryption failed: " . $e->getMessage());
} catch (InvalidKeyException $e) {
    // Invalid key provided
    error_log("Invalid key: " . $e->getMessage());
} catch (UnsupportedCipherException $e) {
    // Required cipher not available
    error_log("Cipher not supported: " . $e->getMessage());
}
```

### Checking Cipher Availability

```php
use Horde\Secret\Cipher\SodiumCipher;
use Horde\Secret\Cipher\AesGcmCipher;
use Horde\Secret\Cipher\BlowfishCipher;

if (SodiumCipher::isSupported()) {
    echo "Sodium available (recommended)\n";
}

if (AesGcmCipher::isSupported()) {
    echo "AES-GCM available\n";
}

if (BlowfishCipher::isSupported()) {
    echo "Blowfish available (legacy)\n";
}
```

## System Requirements

### Modern API (PSR-4)
- PHP ^8.1
- One of:
  - `ext-sodium` (recommended, bundled with PHP 7.2+)
  - `ext-openssl` with AES-GCM support

### Legacy API (PSR-0)
- PHP ^8.1
- `horde/crypt_blowfish` ^2

## Migration Guide

See [UPGRADING.md](UPGRADING.md) for detailed migration instructions.

### Quick Migration Summary

1. **No immediate action required** - PSR-0 API remains fully functional
2. **For new code** - Use PSR-4 `SecretManager::create()`
3. **When ready** - Migrate existing data using lazy or batch migration patterns
4. **PSR-4 can decrypt PSR-0 data** - Seamless compatibility

## Security Considerations

### PSR-0 (Blowfish ECB)
- ❌ No authentication (vulnerable to tampering)
- ❌ ECB mode (pattern leakage)
- ❌ 56-byte key limit
- ⚠️ Use only for backward compatibility

### PSR-4 (Sodium/AES-GCM)
- ✅ Authenticated encryption (AEAD)
- ✅ Modern stream ciphers
- ✅ 256-bit keys
- ✅ Unique nonces per message
- ✅ Constant-time operations (Sodium)

**Recommendation:** Use PSR-4 for all new and sensitive data.

## Data Format

### PSR-4 Format

```
[Magic: 'H']['S'][Version: 1 byte][Payload: variable]
```

- **Magic header**: `HS` (0x48 0x53) for format identification
- **Version byte**:
  - `0x01` - Blowfish ECB (legacy)
  - `0x02` - Sodium XSalsa20-Poly1305
  - `0x03` - AES-256-GCM
- **Payload**: Cipher-specific encrypted data

### PSR-0 Format (Legacy)

```
[Payload: variable]
```

- No header, raw Blowfish ciphertext
- Detected by absence of magic header

## Testing

```bash
# Run all tests
vendor/bin/phpunit

# Run PSR-0 tests only
vendor/bin/phpunit test/Unit/SecretTest.php

# Run PSR-4 tests only
vendor/bin/phpunit --testsuite psr4

# Run integration tests
vendor/bin/phpunit test/Unit/Psr0Psr4IntegrationTest.php
```

## Contributing

Contributions are welcome! Please:

1. Follow PER-1 coding style
2. Add tests for new features
3. Use Conventional Commits format
4. Ensure all tests pass on PHP 8.1+

```bash
# Check coding style
vendor/bin/phpcs

# Run tests
vendor/bin/phpunit
```

## Changelog

See [doc/changelog.yml](doc/changelog.yml) for version history.

## License

LGPL-2.1-only - see [LICENSE](LICENSE) for details.

## Links

- **Homepage**: https://www.horde.org/libraries/Horde_Secret
- **Documentation**: https://www.horde.org/libraries/Horde_Secret
- **GitHub**: https://github.com/horde/Secret
- **Issues**: https://github.com/horde/Secret/issues
- **Packagist**: https://packagist.org/packages/horde/secret

## Support

- **Mailing List**: dev@lists.horde.org
- **GitHub Issues**: https://github.com/horde/Secret/issues

## Credits

- **Authors**: Chuck Hagenbuch, Michael Slusarz
- **Copyright**: 1999-2026 Horde LLC
- **License**: LGPL-2.1-only
