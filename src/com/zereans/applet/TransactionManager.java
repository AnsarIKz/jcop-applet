package com.zereans.applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Secure Transaction Manager for processing secure operations
 */
public class TransactionManager {
    
    // Transaction type constants
    private static final byte TXN_TYPE_TRANSFER = (byte) 0x01;
    private static final byte TXN_TYPE_PAYMENT = (byte) 0x02;
    private static final byte TXN_TYPE_REFUND = (byte) 0x03;
    
    // Buffer sizes
    private static final short TXN_DATA_LENGTH = 64;
    private static final short SIGNATURE_LENGTH = 256; // RSA 2048 signature
    private static final short HASH_LENGTH = 32;
    
    // Transaction buffers
    private byte[] transactionData;
    private byte[] signatureBuffer;
    private byte[] hashBuffer;
    private short transactionId;
    private boolean isInitialized;
    
    // Cryptographic objects
    private Signature signature;
    private MessageDigest digest;
    private RandomData random;
    
    /**
     * Secure constructor with proper initialization
     */
    public TransactionManager() {
        transactionData = new byte[TXN_DATA_LENGTH];
        signatureBuffer = new byte[SIGNATURE_LENGTH];
        hashBuffer = new byte[HASH_LENGTH];
        transactionId = 0;
        isInitialized = false;
        
        try {
            signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            isInitialized = true;
        } catch (Exception e) {
            // Handle initialization errors
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }
    
    /**
     * Create secure transaction with proper validation and atomic operations
     */
    public boolean createTransaction(byte[] data, short offset, short length, 
                                   PrivateKey privateKey) {
        if (!isInitialized || length > TXN_DATA_LENGTH || length <= 0) {
            return false;
        }
        
        // Store original state for rollback
        short originalId = transactionId;
        
        try {
            // Clear previous transaction data
            clearTransaction();
            
            // Copy transaction data
            Util.arrayCopy(data, offset, transactionData, (short) 0, length);
            
            // Generate secure hash of transaction data
            short hashLength = digest.doFinal(transactionData, (short) 0, length, 
                                           hashBuffer, (short) 0);
            
            if (hashLength != HASH_LENGTH) {
                // Rollback on hash failure
                transactionId = originalId;
                return false;
            }
            
            // Sign the hash with private key
            signature.init(privateKey, Signature.MODE_SIGN);
            short sigLength = signature.sign(hashBuffer, (short) 0, HASH_LENGTH, 
                                            signatureBuffer, (short) 0);
            
            if (sigLength != SIGNATURE_LENGTH) {
                // Rollback on signature failure
                transactionId = originalId;
                clearTransaction();
                return false;
            }
            
            // Only increment ID on success
            transactionId++;
            return true;
        } catch (Exception e) {
            // Rollback on any exception
            transactionId = originalId;
            clearTransaction();
            return false;
        }
    }
    
    /**
     * Verify transaction signature securely
     */
    public boolean verifyTransaction(byte[] data, short offset, short length,
                                   PublicKey publicKey) {
        if (!isInitialized || length > TXN_DATA_LENGTH || length <= 0) {
            return false;
        }
        
        try {
            // Compute hash of input data
            byte[] computedHash = new byte[HASH_LENGTH];
            short hashLength = digest.doFinal(data, offset, length, computedHash, (short) 0);
            
            if (hashLength != HASH_LENGTH) {
                return false;
            }
            
            // Verify signature
            signature.init(publicKey, Signature.MODE_VERIFY);
            boolean isValid = signature.verify(computedHash, (short) 0, HASH_LENGTH, 
                                             signatureBuffer, (short) 0, SIGNATURE_LENGTH);
            
            // Clear computed hash
            Util.arrayFillNonAtomic(computedHash, (short) 0, HASH_LENGTH, (byte) 0x00);
            
            return isValid;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get transaction data securely
     */
    public short getTransactionData(byte[] buffer, short offset) {
        if (!isInitialized) {
            return 0;
        }
        
        try {
            Util.arrayCopy(transactionData, (short) 0, buffer, offset, 
                          (short) transactionData.length);
            return (short) transactionData.length;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Get transaction signature securely
     */
    public short getSignature(byte[] buffer, short offset) {
        if (!isInitialized) {
            return 0;
        }
        
        try {
            Util.arrayCopy(signatureBuffer, (short) 0, buffer, offset, 
                          SIGNATURE_LENGTH);
            return SIGNATURE_LENGTH;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Get transaction ID
     */
    public short getTransactionId() {
        return transactionId;
    }
    
    /**
     * Secure transaction data clearing
     */
    public void clearTransaction() {
        if (!isInitialized) {
            return;
        }
        
        // Clear all transaction-related buffers
        Util.arrayFillNonAtomic(transactionData, (short) 0, 
                               (short) transactionData.length, (byte) 0x00);
        Util.arrayFillNonAtomic(signatureBuffer, (short) 0, 
                               (short) signatureBuffer.length, (byte) 0x00);
        Util.arrayFillNonAtomic(hashBuffer, (short) 0, 
                               (short) hashBuffer.length, (byte) 0x00);
    }
    
    /**
     * Check if transaction manager is initialized
     */
    public boolean isInitialized() {
        return isInitialized;
    }
    
    /**
     * Get transaction hash
     */
    public short getTransactionHash(byte[] buffer, short offset) {
        if (!isInitialized) {
            return 0;
        }
        
        try {
            Util.arrayCopy(hashBuffer, (short) 0, buffer, offset, HASH_LENGTH);
            return HASH_LENGTH;
        } catch (Exception e) {
            return 0;
        }
    }
}
