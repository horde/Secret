# Upgrading Horde_Secret

## From 2.x to 3.x

### Overview

Horde_Secret 3.0 introduces a **dual-stack architecture**:

- **PSR-0 API** (`Horde_Secret`) - Unchanged, 100% backward compatible
- **PSR-4 API** (`Horde\Secret\SecretManager`) - Modern authenticated encryption

### For Existing Users: Zero Breaking Changes

**If you're using the PSR-0 API (`Horde_Secret`), nothing changes:**

```php
// This code works exactly the same in 3.0
$secret = new Horde_Secret();
$encrypted = $secret->write($key, $message);
$decrypted = $secret->read($key, $encrypted);
```

✅ **No code changes required**
✅ **No data migration required**
✅ **Drop-in compatible upgrade**

### For New Projects: Modern PSR-4 API

New projects should use the PSR-4 API for modern authenticated encryption:

```php
use Horde\Secret\SecretManager;

// Automatic cipher selection (prefers Sodium)
$secret = SecretManager::create($key);

// Encrypt with authenticated encryption
$encrypted = $secret->encrypt($plaintext);

// Decrypt
$decrypted = $secret->decrypt($encrypted);
```

**Key improvements over PSR-0:**
- ✅ **Authenticated encryption** (AEAD) prevents tampering
- ✅ **Libsodium XSalsa20-Poly1305** (primary cipher)
- ✅ **AES-256-GCM** fallback when Sodium unavailable
- ✅ **Type-safe** (strict types, typed properties)
- ✅ **Immutable** value objects
- ✅ **Automatic legacy data detection**

### Migration Path (Optional)

When you're ready to upgrade existing data to modern encryption:

#### Step 1: Update Code to PSR-4

**Before (PSR-0):**
```php
$secret = new Horde_Secret();
$decrypted = $secret->read($key, $ciphertext);
```

**After (PSR-4):**
```php
use Horde\Secret\SecretManager;

$secret = SecretManager::create($key);
$decrypted = $secret->decrypt($ciphertext);  // Works with old data!
```

**Important:** PSR-4 can decrypt PSR-0 encrypted data automatically.

#### Step 2: Lazy Migration (Recommended)

Re-encrypt data on read (no downtime):

```php
use Horde\Secret\SecretManager;

$secret = SecretManager::create($key);

// Decrypt (works with old or new format)
$decrypted = $secret->decrypt($storedCiphertext);

// Check if needs upgrade
if ($secret->needsReEncryption($storedCiphertext)) {
    // Re-encrypt with modern cipher
    $newCiphertext = $secret->encrypt($decrypted);

    // Update database
    $db->update('table', [
        'encrypted_field' => $newCiphertext->toString()
    ], ['id' => $recordId]);
}
```

#### Step 3: Batch Migration (Alternative)

Migrate all data at once:

```php
use Horde\Secret\SecretManager;

$secret = SecretManager::create($key);

// Process all records
foreach ($db->query('SELECT id, encrypted_field FROM table') as $row) {
    $oldCiphertext = $row['encrypted_field'];

    // Decrypt old format
    $plaintext = $secret->decrypt($oldCiphertext);

    // Re-encrypt with modern cipher
    $newCiphertext = $secret->encrypt($plaintext);

    // Update record
    $db->update('table', [
        'encrypted_field' => $newCiphertext->toString()
    ], ['id' => $row['id']]);
}
```

### Detecting Data Format

```php
use Horde\Secret\EncryptedData;

// Check if data has modern format
if (EncryptedData::hasHeader($ciphertext)) {
    echo "Modern format (PSR-4)\n";
} else {
    echo "Legacy format (PSR-0)\n";
}

// Or use SecretManager helper
$secret = SecretManager::create($key);
if ($secret->needsReEncryption($ciphertext)) {
    echo "Should upgrade to modern cipher\n";
}
```

### Cipher Selection

```php
use Horde\Secret\SecretManager;

// Automatic (prefers Sodium, falls back to AES-GCM)
$secret = SecretManager::create($key);

// Explicit cipher selection
$secret = SecretManager::withSodium($key);    // XSalsa20-Poly1305
$secret = SecretManager::withAesGcm($key);    // AES-256-GCM
$secret = SecretManager::withBlowfish($key);  // Legacy only

// Check current cipher
echo $secret->getCipherName();     // e.g., "XSalsa20-Poly1305"
echo $secret->getCipherVersion();  // e.g., 0x02
```

### Cross-Version Compatibility

PSR-4 can decrypt data encrypted with any cipher version:

```php
// Data encrypted with AES-GCM
$aesSecret = SecretManager::withAesGcm($key);
$aesCiphertext = $aesSecret->encrypt('data');

// Can decrypt with Sodium manager (auto-detects)
$sodiumSecret = SecretManager::withSodium($key);
$decrypted = $sodiumSecret->decrypt($aesCiphertext);  // Works!

// Check if should re-encrypt to Sodium
if ($sodiumSecret->needsReEncryption($aesCiphertext)) {
    $newCiphertext = $sodiumSecret->encrypt($decrypted);
}
```

### System Requirements

**PSR-0 (`Horde_Secret`):**
- PHP ^8.1
- horde/crypt_blowfish ^2

**PSR-4 (`Horde\Secret\SecretManager`):**
- PHP ^8.1
- One of:
  - `ext-sodium` (recommended, bundled with PHP 7.2+)
  - `ext-openssl` with AES-GCM support

Check cipher availability:

```php
use Horde\Secret\Cipher\SodiumCipher;
use Horde\Secret\Cipher\AesGcmCipher;

if (SodiumCipher::isSupported()) {
    echo "Sodium available (recommended)\n";
}

if (AesGcmCipher::isSupported()) {
    echo "AES-GCM available\n";
}
```

### Cookie Management Removed from PSR-4

PSR-0 includes cookie/session key management. PSR-4 removes this (separation of concerns).

**Migration strategy:**

**Before (PSR-0 with cookies):**
```php
$secret = new Horde_Secret([
    'cookie_domain' => '.example.com',
    'cookie_path' => '/app',
    'cookie_ssl' => true,
]);

$key = $secret->setKey('myapp');
$encrypted = $secret->write($key, $data);
```

**After (PSR-4 - handle keys separately):**
```php
use Horde\Secret\SecretManager;

// Manage key in your session/cookie layer
if (!isset($_SESSION['encryption_key'])) {
    $_SESSION['encryption_key'] = random_bytes(32);
}

$key = $_SESSION['encryption_key'];
$secret = SecretManager::create($key);
$encrypted = $secret->encrypt($data);
```

Or use Horde_Session:

```php
use Horde_Session;
use Horde\Secret\SecretManager;

$session = new Horde_Session();
if (!$session->exists('horde', 'secret_key')) {
    $session->set('horde', 'secret_key', random_bytes(32));
}

$key = $session->get('horde', 'secret_key');
$secret = SecretManager::create($key);
```

### Exception Hierarchy

**PSR-0:**
```php
try {
    $secret->read($key, $ciphertext);
} catch (Horde_Secret_Exception $e) {
    // All errors
}
```

**PSR-4:**
```php
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\InvalidKeyException;
use Horde\Secret\Exception\UnsupportedCipherException;

try {
    $secret->decrypt($ciphertext);
} catch (DecryptionException $e) {
    // Decryption or authentication failure
} catch (InvalidKeyException $e) {
    // Invalid key provided
} catch (UnsupportedCipherException $e) {
    // Cipher not available on system
}
```

### Testing Your Migration

Run tests to verify compatibility:

```bash
# Run all tests (PSR-0 + PSR-4 + integration)
vendor/bin/phpunit

# Run only PSR-0 tests
vendor/bin/phpunit test/Unit/SecretTest.php

# Run only PSR-4 tests
vendor/bin/phpunit test/Unit/SecretManagerTest.php

# Run integration tests
vendor/bin/phpunit test/Unit/Psr0Psr4IntegrationTest.php
```

### Performance Considerations

- **Sodium (XSalsa20-Poly1305)**: Fastest, constant-time operations
- **AES-GCM**: Good performance, hardware-accelerated on modern CPUs
- **Blowfish ECB**: Slowest, no authentication, legacy only

Benchmark on your system:

```php
use Horde\Secret\SecretManager;
use Horde\Secret\Cipher\BlowfishCipher;

$key = random_bytes(32);
$data = str_repeat('x', 1000);

// Sodium
$start = microtime(true);
$sodium = SecretManager::withSodium($key);
for ($i = 0; $i < 1000; $i++) {
    $enc = $sodium->encrypt($data);
    $sodium->decrypt($enc);
}
$sodiumTime = microtime(true) - $start;

// AES-GCM
$start = microtime(true);
$aes = SecretManager::withAesGcm($key);
for ($i = 0; $i < 1000; $i++) {
    $enc = $aes->encrypt($data);
    $aes->decrypt($enc);
}
$aesTime = microtime(true) - $start;

echo "Sodium: {$sodiumTime}s\n";
echo "AES-GCM: {$aesTime}s\n";
```

### Security Considerations

**PSR-0 (Blowfish ECB) limitations:**
- ❌ No authentication (vulnerable to tampering)
- ❌ ECB mode (pattern leakage for repetitive data)
- ❌ 56-byte key limit

**PSR-4 improvements:**
- ✅ Authenticated encryption (AEAD)
- ✅ Modern stream ciphers with proper modes
- ✅ Full 256-bit keys
- ✅ Unique nonces per message

**Recommendation:** Migrate to PSR-4 for new and sensitive data.

### Troubleshooting

**"No supported cipher available"**

Install Sodium or OpenSSL:

```bash
# Check extensions
php -m | grep -E 'sodium|openssl'

# Install Sodium (usually bundled with PHP 7.2+)
# On Ubuntu/Debian:
apt-get install php-sodium

# On RHEL/CentOS:
yum install php-sodium
```

**"Cannot decrypt legacy format"**

Ensure `horde/crypt_blowfish` is installed:

```bash
composer require horde/crypt_blowfish:^2
```

**"Wrong key" errors after migration**

Verify you're using the same key for decryption:

```php
// PSR-4 uses HKDF key derivation internally
// Use the SAME original key, not a derived key
$secret = SecretManager::create($originalKey);
```

### FAQ

**Q: Do I need to migrate immediately?**
A: No. PSR-0 API remains fully supported. Migrate when convenient.

**Q: Can I use both APIs in the same application?**
A: Yes. They work independently. PSR-4 can decrypt PSR-0 data.

**Q: Will 4.0 remove PSR-0 support?**
A: No plans to remove it. PSR-0 will be maintained for backward compatibility.

**Q: Which cipher should I use?**
A: Use `SecretManager::create()` for automatic selection (Sodium preferred).

**Q: Can I decrypt PSR-4 data with PSR-0?**
A: No. PSR-0 has no knowledge of the PSR-4 format headers.

**Q: How do I handle key rotation?**
A: Decrypt with old key, re-encrypt with new key:

```php
$oldSecret = SecretManager::create($oldKey);
$newSecret = SecretManager::create($newKey);

$plaintext = $oldSecret->decrypt($oldCiphertext);
$newCiphertext = $newSecret->encrypt($plaintext);
```

### Getting Help

- **Issues**: https://github.com/horde/Secret/issues
- **Documentation**: https://www.horde.org/libraries/Horde_Secret
- **Mailing list**: dev@lists.horde.org
