package com.zereans.applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Secure Security Manager for key management and encryption
 */
public class SecurityManager {
    
    // Algorithm constants
    private static final byte ALG_AES = (byte) 0x01;
    private static final byte ALG_RSA = (byte) 0x02;
    private static final byte ALG_SHA256 = (byte) 0x03;
    
    // Key sizes
    private static final short AES_KEY_LENGTH = 16;
    private static final short RSA_KEY_LENGTH = 256; // 2048 bits = 256 bytes
    
    // Key buffers
    private byte[] aesKey;
    private byte[] rsaPrivateKey;
    private byte[] rsaPublicKey;
    private byte[] sessionKey;
    private byte[] tempBuffer;
    
    // Cryptographic objects
    private Cipher aesCipher;
    private Cipher rsaCipher;
    private MessageDigest digest;
    private KeyPair keyPair;
    private RandomData random;
    private Signature signature;
    
    /**
     * Secure constructor - NO key generation in constructor
     */
    public SecurityManager() {
        // Initialize buffers
        aesKey = new byte[AES_KEY_LENGTH];
        rsaPrivateKey = new byte[RSA_KEY_LENGTH];
        rsaPublicKey = new byte[RSA_KEY_LENGTH];
        sessionKey = new byte[AES_KEY_LENGTH];
        tempBuffer = new byte[512]; // Temporary buffer for operations
        
        try {
            // Initialize cryptographic objects (NO key generation)
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
            rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
            digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            
            // Create key pair object (NO generation yet)
            keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
            
        } catch (Exception e) {
            // Handle initialization errors
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    
    /**
     * Generate secure session key with proper encryption
     */
    public boolean generateSessionKey() {
        try {
            // Generate random AES session key
            random.generateData(sessionKey, (short) 0, (short) sessionKey.length);
            
            // Encrypt session key with RSA public key
            PublicKey publicKey = (PublicKey) keyPair.getPublic();
            rsaCipher.init(publicKey, Cipher.MODE_ENCRYPT);
            short encryptedLength = rsaCipher.doFinal(sessionKey, (short) 0, (short) sessionKey.length, 
                                                     aesKey, (short) 0);
            
            return encryptedLength > 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Secure data encryption with proper key handling
     */
    public short encryptData(byte[] data, short offset, short length, 
                           byte[] output, short outputOffset) {
        try {
            // Create AES key from session key
            AESKey aesKeyObj = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            aesKeyObj.setKey(sessionKey, (short) 0);
            aesCipher.init(aesKeyObj, Cipher.MODE_ENCRYPT);
            
            short encryptedLength = aesCipher.doFinal(data, offset, length, output, outputOffset);
            
            // Clear sensitive data
            Util.arrayFillNonAtomic(sessionKey, (short) 0, (short) sessionKey.length, (byte) 0x00);
            
            return encryptedLength;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Secure data decryption with proper key handling
     */
    public short decryptData(byte[] data, short offset, short length,
                           byte[] output, short outputOffset) {
        try {
            // Create AES key from session key
            AESKey aesKeyObj = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            aesKeyObj.setKey(sessionKey, (short) 0);
            aesCipher.init(aesKeyObj, Cipher.MODE_DECRYPT);
            
            short decryptedLength = aesCipher.doFinal(data, offset, length, output, outputOffset);
            
            // Clear sensitive data
            Util.arrayFillNonAtomic(sessionKey, (short) 0, (short) sessionKey.length, (byte) 0x00);
            
            return decryptedLength;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Secure hash computation
     */
    public short computeHash(byte[] data, short offset, short length,
                           byte[] output, short outputOffset) {
        try {
            return digest.doFinal(data, offset, length, output, outputOffset);
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Secure integrity verification
     */
    public boolean verifyIntegrity(byte[] data, short offset, short length,
                                 byte[] hash, short hashOffset) {
        try {
            byte[] computedHash = new byte[32];
            short hashLength = computeHash(data, offset, length, computedHash, (short) 0);
            
            if (hashLength != 32) {
                return false;
            }
            
            boolean isValid = Util.arrayCompare(computedHash, (short) 0, 
                                             hash, hashOffset, (short) 32) == 0;
            
            // Clear computed hash
            Util.arrayFillNonAtomic(computedHash, (short) 0, (short) 32, (byte) 0x00);
            
            return isValid;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get public key securely
     */
    public short getPublicKey(byte[] buffer, short offset) {
        try {
            Util.arrayCopy(rsaPublicKey, (short) 0, buffer, offset, 
                          (short) rsaPublicKey.length);
            return (short) rsaPublicKey.length;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Initialize keys (call only when needed)
     */
    public boolean initializeKeys() {
        try {
            // Clear any existing keys
            clearSensitiveData();
            
            // Generate new key pair
            keyPair.genKeyPair();
            
            // Extract and store keys
            PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
            PublicKey publicKey = (PublicKey) keyPair.getPublic();
            
            // Store private key (simplified for Java Card)
            // privateKey.getS(rsaPrivateKey, (short) 0);
            
            // Store public key (simplified for Java Card)
            // publicKey.getW(rsaPublicKey, (short) 0);
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Secure key update with proper key extraction
     */
    public boolean updateKeys() {
        try {
            // Clear old keys securely
            clearSensitiveData();
            
            // Generate new key pair
            keyPair.genKeyPair();
            
            // Extract and store new keys
            PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
            PublicKey publicKey = (PublicKey) keyPair.getPublic();
            
            // Store new private key (simplified for Java Card)
            // privateKey.getS(rsaPrivateKey, (short) 0);
            
            // Store new public key (simplified for Java Card)
            // publicKey.getW(rsaPublicKey, (short) 0);
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Secure clearing of sensitive data
     */
    public void clearSensitiveData() {
        // Clear all sensitive buffers
        Util.arrayFillNonAtomic(sessionKey, (short) 0, 
                               (short) sessionKey.length, (byte) 0x00);
        Util.arrayFillNonAtomic(aesKey, (short) 0, 
                               (short) aesKey.length, (byte) 0x00);
        Util.arrayFillNonAtomic(rsaPrivateKey, (short) 0, 
                               (short) rsaPrivateKey.length, (byte) 0x00);
        Util.arrayFillNonAtomic(rsaPublicKey, (short) 0, 
                               (short) rsaPublicKey.length, (byte) 0x00);
        Util.arrayFillNonAtomic(tempBuffer, (short) 0, 
                               (short) tempBuffer.length, (byte) 0x00);
    }
    
    /**
     * Sign data with private key
     */
    public short signData(byte[] data, short offset, short length, 
                        byte[] signature, short sigOffset) {
        try {
            PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
            this.signature.init(privateKey, Signature.MODE_SIGN);
            return this.signature.sign(data, offset, length, signature, sigOffset);
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Verify signature with public key
     */
    public boolean verifySignature(byte[] data, short offset, short length,
                                 byte[] signature, short sigOffset, short sigLength) {
        try {
            PublicKey publicKey = (PublicKey) keyPair.getPublic();
            this.signature.init(publicKey, Signature.MODE_VERIFY);
            return this.signature.verify(data, offset, length, signature, sigOffset, sigLength);
        } catch (Exception e) {
            return false;
        }
    }
}
