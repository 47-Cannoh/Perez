/**
 * Secure Encryption System for Bot
 * Uses AES-256-GCM encryption with PBKDF2 key derivation
 * Includes integrity checks and secure key management
 */

class BotEncryptionSystem {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
        this.ivLength = 12; // 96 bits for GCM
        this.saltLength = 16;
        this.iterations = 100000;
        this.hash = 'SHA-256';
    }

    /**
     * Generate a secure encryption key from a password
     * @param {string} password - The password to derive key from
     * @param {Uint8Array} salt - Salt for key derivation
     * @returns {Promise<CryptoKey>} - Derived encryption key
     */
    async generateKey(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.iterations,
                hash: this.hash
            },
            keyMaterial,
            { name: this.algorithm, length: this.keyLength },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Generate random bytes
     * @param {number} length - Number of bytes to generate
     * @returns {Uint8Array} - Random bytes
     */
    generateRandomBytes(length) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    /**
     * Encrypt any data
     * @param {any} data - Data to encrypt (string, object, number, etc.)
     * @param {string} password - Encryption password
     * @returns {Promise<string>} - Encrypted string in format: salt.iv.ciphertext.tag
     */
    async encrypt(data, password) {
        try {
            // Convert data to string
            const dataString = typeof data === 'string' ? data : JSON.stringify(data);
            
            // Generate random salt and IV
            const salt = this.generateRandomBytes(this.saltLength);
            const iv = this.generateRandomBytes(this.ivLength);
            
            // Derive key from password
            const key = await this.generateKey(password, salt);
            
            // Encrypt the data
            const encoder = new TextEncoder();
            const encodedData = encoder.encode(dataString);
            
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: this.algorithm,
                    iv: iv,
                    tagLength: 128
                },
                key,
                encodedData
            );
            
            // Extract authentication tag (last 16 bytes)
            const ciphertext = new Uint8Array(encrypted.slice(0, -16));
            const tag = new Uint8Array(encrypted.slice(-16));
            
            // Combine all components
            const combined = new Uint8Array(
                salt.length + iv.length + ciphertext.length + tag.length
            );
            combined.set(salt, 0);
            combined.set(iv, salt.length);
            combined.set(ciphertext, salt.length + iv.length);
            combined.set(tag, salt.length + iv.length + ciphertext.length);
            
            // Convert to base64 for storage/transmission
            return this.uint8ArrayToBase64(combined);
            
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt data');
        }
    }

    /**
     * Decrypt data
     * @param {string} encryptedData - Encrypted string from encrypt()
     * @param {string} password - Encryption password
     * @returns {Promise<any>} - Original decrypted data
     */
    async decrypt(encryptedData, password) {
        try {
            // Convert from base64
            const combined = this.base64ToUint8Array(encryptedData);
            
            // Extract components
            const salt = combined.slice(0, this.saltLength);
            const iv = combined.slice(this.saltLength, this.saltLength + this.ivLength);
            const ciphertextAndTag = combined.slice(this.saltLength + this.ivLength);
            
            // Split ciphertext and tag (tag is last 16 bytes)
            const ciphertext = ciphertextAndTag.slice(0, -16);
            const tag = ciphertextAndTag.slice(-16);
            
            // Combine ciphertext and tag for decryption
            const encrypted = new Uint8Array(ciphertext.length + tag.length);
            encrypted.set(ciphertext, 0);
            encrypted.set(tag, ciphertext.length);
            
            // Derive key from password
            const key = await this.generateKey(password, salt);
            
            // Decrypt the data
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: this.algorithm,
                    iv: iv,
                    tagLength: 128
                },
                key,
                encrypted
            );
            
            // Convert back to original format
            const decoder = new TextDecoder();
            const decryptedString = decoder.decode(decrypted);
            
            // Try to parse as JSON, if fails return as string
            try {
                return JSON.parse(decryptedString);
            } catch {
                return decryptedString;
            }
            
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt data. Wrong password or corrupted data.');
        }
    }

    /**
     * Encrypt with compression (for large data)
     * @param {any} data - Data to encrypt
     * @param {string} password - Encryption password
     * @returns {Promise<string>} - Compressed and encrypted data
     */
    async encryptWithCompression(data, password) {
        const dataString = typeof data === 'string' ? data : JSON.stringify(data);
        const compressed = await this.compress(dataString);
        return this.encrypt(compressed, password);
    }

    /**
     * Decrypt with decompression
     * @param {string} encryptedData - Encrypted data
     * @param {string} password - Encryption password
     * @returns {Promise<any>} - Original data
     */
    async decryptWithCompression(encryptedData, password) {
        const compressed = await this.decrypt(encryptedData, password);
        const decompressed = await this.decompress(compressed);
        
        try {
            return JSON.parse(decompressed);
        } catch {
            return decompressed;
        }
    }

    /**
     * Compress string using gzip
     * @param {string} string - String to compress
     * @returns {Promise<string>} - Base64 encoded compressed data
     */
    async compress(string) {
        const encoder = new TextEncoder();
        const data = encoder.encode(string);
        
        const cs = new CompressionStream('gzip');
        const writer = cs.writable.getWriter();
        writer.write(data);
        writer.close();
        
        const compressed = await new Response(cs.readable).arrayBuffer();
        return this.uint8ArrayToBase64(new Uint8Array(compressed));
    }

    /**
     * Decompress gzip compressed string
     * @param {string} compressed - Base64 encoded compressed data
     * @returns {Promise<string>} - Decompressed string
     */
    async decompress(compressed) {
        const data = this.base64ToUint8Array(compressed);
        
        const ds = new DecompressionStream('gzip');
        const writer = ds.writable.getWriter();
        writer.write(data);
        writer.close();
        
        const decompressed = await new Response(ds.readable).arrayBuffer();
        const decoder = new TextDecoder();
        return decoder.decode(decompressed);
    }

    /**
     * Convert Uint8Array to base64
     * @param {Uint8Array} array - Array to convert
     * @returns {string} - Base64 string
     */
    uint8ArrayToBase64(array) {
        return btoa(String.fromCharCode(...array));
    }

    /**
     * Convert base64 to Uint8Array
     * @param {string} base64 - Base64 string
     * @returns {Uint8Array} - Converted array
     */
    base64ToUint8Array(base64) {
        return new Uint8Array([...atob(base64)].map(char => char.charCodeAt(0)));
    }

    /**
     * Generate secure password
     * @param {number} length - Password length (default: 32)
     * @returns {string} - Secure random password
     */
    generatePassword(length = 32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        const randomValues = crypto.getRandomValues(new Uint8Array(length));
        let password = '';
        
        for (let i = 0; i < length; i++) {
            password += chars[randomValues[i] % chars.length];
        }
        
        return password;
    }

    /**
     * Hash password for storage (using PBKDF2)
     * @param {string} password - Password to hash
     * @param {Uint8Array} salt - Salt for hashing
     * @returns {Promise<string>} - Hashed password
     */
    async hashPassword(password, salt = this.generateRandomBytes(16)) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits']
        );
        
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            256
        );
        
        const hashArray = Array.from(new Uint8Array(derivedBits));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
        
        return `${saltHex}:${hashHex}`;
    }

    /**
     * Verify hashed password
     * @param {string} password - Password to verify
     * @param {string} hashedPassword - Stored hashed password
     * @returns {Promise<boolean>} - True if password matches
     */
    async verifyPassword(password, hashedPassword) {
        const [saltHex, storedHash] = hashedPassword.split(':');
        const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        
        const newHash = await this.hashPassword(password, salt);
        return newHash === hashedPassword;
    }

    /**
     * Encrypt file/blob data
     * @param {File|Blob} file - File to encrypt
     * @param {string} password - Encryption password
     * @returns {Promise<string>} - Encrypted file data
     */
    async encryptFile(file, password) {
        const arrayBuffer = await file.arrayBuffer();
        const data = new Uint8Array(arrayBuffer);
        const dataString = this.uint8ArrayToBase64(data);
        
        return this.encrypt(dataString, password);
    }

    /**
     * Decrypt file data
     * @param {string} encryptedData - Encrypted file data
     * @param {string} password - Encryption password
     * @param {string} mimeType - Original file mime type
     * @returns {Promise<Blob>} - Decrypted file as Blob
     */
    async decryptFile(encryptedData, password, mimeType = 'application/octet-stream') {
        const decrypted = await this.decrypt(encryptedData, password);
        const data = this.base64ToUint8Array(decrypted);
        
        return new Blob([data], { type: mimeType });
    }
}

// Example usage with bot integration
class SecureBot {
    constructor(config = {}) {
        this.encryption = new BotEncryptionSystem();
        this.encryptionKey = config.password || this.encryption.generatePassword();
        this.autoEncrypt = config.autoEncrypt !== false;
        
        console.log('🔐 Secure Bot Encryption System Initialized');
        console.log('Store this key securely:', this.encryptionKey);
    }

    /**
     * Send encrypted message
     */
    async sendMessage(message, options = {}) {
        let content = message;
        
        if (this.autoEncrypt && options.encrypt !== false) {
            content = await this.encryption.encrypt(message, this.encryptionKey);
            content = `🔒 ENCRYPTED:${content}`;
        }
        
        // Send message through your bot's API
        console.log('Sending message:', content);
        // Your bot's send logic here
        
        return { success: true, encrypted: this.autoEncrypt };
    }

    /**
     * Receive and decrypt message
     */
    async receiveMessage(message) {
        if (message.startsWith('🔒 ENCRYPTED:')) {
            try {
                const encryptedData = message.substring(12);
                const decrypted = await this.encryption.decrypt(encryptedData, this.encryptionKey);
                console.log('Decrypted message:', decrypted);
                return decrypted;
            } catch (error) {
                console.error('Failed to decrypt message:', error);
                return message;
            }
        }
        return message;
    }

    /**
     * Store encrypted configuration
     */
    async saveConfig(config) {
        const encrypted = await this.encryption.encrypt(config, this.encryptionKey);
        // Save to database or file
        localStorage.setItem('bot_config_encrypted', encrypted);
        return encrypted;
    }

    /**
     * Load and decrypt configuration
     */
    async loadConfig() {
        const encrypted = localStorage.getItem('bot_config_encrypted');
        if (!encrypted) return null;
        
        try {
            return await this.encryption.decrypt(encrypted, this.encryptionKey);
        } catch (error) {
            console.error('Failed to load config:', error);
            return null;
        }
    }

    /**
     * Change encryption key (re-encrypts all data)
     */
    async changeKey(newPassword, oldPassword = this.encryptionKey) {
        try {
            // Re-encrypt stored data with new key
            const oldConfig = await this.loadConfig();
            this.encryptionKey = newPassword;
            
            if (oldConfig) {
                await this.saveConfig(oldConfig);
            }
            
            console.log('✅ Encryption key changed successfully');
            return true;
        } catch (error) {
            console.error('Failed to change key:', error);
            return false;
        }
    }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { BotEncryptionSystem, SecureBot };
}

if (typeof window !== 'undefined') {
    window.BotEncryptionSystem = BotEncryptionSystem;
    window.SecureBot = SecureBot;
}
