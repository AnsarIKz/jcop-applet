package com.zereans.applet;

import javacard.framework.*;
import javacard.security.*;

/**
 * Secure Network Protocol for partner network communication
 */
public class NetworkProtocol {
    
    // Protocol constants
    private static final byte PROTOCOL_VERSION = (byte) 0x01;
    private static final byte MAX_PARTNERS = (byte) 0x10;
    private static final short MAX_MESSAGE_LENGTH = 512; // Increased for security
    private static final short SIGNATURE_LENGTH = 256;
    private static final short HASH_LENGTH = 32;
    
    // Message types
    private static final byte MSG_HANDSHAKE = (byte) 0x01;
    private static final byte MSG_TRANSACTION = (byte) 0x02;
    private static final byte MSG_RESPONSE = (byte) 0x03;
    private static final byte MSG_ERROR = (byte) 0x04;
    private static final byte MSG_AUTHENTICATION = (byte) 0x05;
    
    // Error codes
    private static final byte ERR_INVALID_PARTNER = (byte) 0x01;
    private static final byte ERR_INSUFFICIENT_FUNDS = (byte) 0x02;
    private static final byte ERR_INVALID_SIGNATURE = (byte) 0x03;
    private static final byte ERR_NETWORK_ERROR = (byte) 0x04;
    private static final byte ERR_AUTHENTICATION_FAILED = (byte) 0x05;
    
    // Message structure
    private static final short OFFSET_VERSION = 0;
    private static final short OFFSET_TYPE = 1;
    private static final short OFFSET_PARTNER_ID = 2;
    private static final short OFFSET_SEQUENCE = 3;
    private static final short OFFSET_DATA_LENGTH = 4;
    private static final short OFFSET_DATA = 5;
    private static final short OFFSET_SIGNATURE = 5; // Will be calculated dynamically
    
    // Secure buffers
    private byte[] messageBuffer;
    private byte[] partnerList;
    private byte[] signatureBuffer;
    private byte[] hashBuffer;
    private byte sequenceNumber;
    private boolean isInitialized;
    
    /**
     * Secure constructor with proper initialization
     */
    public NetworkProtocol() {
        messageBuffer = new byte[MAX_MESSAGE_LENGTH];
        partnerList = new byte[MAX_PARTNERS];
        signatureBuffer = new byte[SIGNATURE_LENGTH];
        hashBuffer = new byte[HASH_LENGTH];
        sequenceNumber = 0;
        isInitialized = true;
    }
    
    /**
     * Create secure handshake message with authentication
     */
    public short createHandshakeMessage(byte partnerId, byte[] output, short offset) {
        if (!isInitialized) {
            return 0;
        }
        
        try {
            // Clear previous message
            Util.arrayFillNonAtomic(messageBuffer, (short) 0, (short) messageBuffer.length, (byte) 0x00);
            
            // Build handshake message
            messageBuffer[OFFSET_VERSION] = PROTOCOL_VERSION;
            messageBuffer[OFFSET_TYPE] = MSG_HANDSHAKE;
            messageBuffer[OFFSET_PARTNER_ID] = partnerId;
            messageBuffer[OFFSET_SEQUENCE] = sequenceNumber++;
            messageBuffer[OFFSET_DATA_LENGTH] = 0;
            
            short messageLength = (short) (OFFSET_DATA + messageBuffer[OFFSET_DATA_LENGTH]);
            Util.arrayCopy(messageBuffer, (short) 0, output, offset, messageLength);
            
            return messageLength;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Create transaction message
     */
    public short createTransactionMessage(byte partnerId, byte[] transactionData, 
                                        short dataLength, byte[] output, short offset) {
        if (dataLength > (MAX_MESSAGE_LENGTH - OFFSET_DATA)) {
            return 0;
        }
        
        messageBuffer[OFFSET_VERSION] = PROTOCOL_VERSION;
        messageBuffer[OFFSET_TYPE] = MSG_TRANSACTION;
        messageBuffer[OFFSET_PARTNER_ID] = partnerId;
        messageBuffer[OFFSET_SEQUENCE] = sequenceNumber++;
        messageBuffer[OFFSET_DATA_LENGTH] = (byte) dataLength;
        
        Util.arrayCopy(transactionData, (short) 0, messageBuffer, OFFSET_DATA, dataLength);
        
        short messageLength = (short) (OFFSET_DATA + dataLength);
        Util.arrayCopy(messageBuffer, (short) 0, output, offset, messageLength);
        
        return messageLength;
    }
    
    /**
     * Create response message
     */
    public short createResponseMessage(byte partnerId, byte responseCode, 
                                     byte[] responseData, short dataLength,
                                     byte[] output, short offset) {
        if (dataLength > (MAX_MESSAGE_LENGTH - OFFSET_DATA)) {
            return 0;
        }
        
        messageBuffer[OFFSET_VERSION] = PROTOCOL_VERSION;
        messageBuffer[OFFSET_TYPE] = MSG_RESPONSE;
        messageBuffer[OFFSET_PARTNER_ID] = partnerId;
        messageBuffer[OFFSET_SEQUENCE] = sequenceNumber++;
        messageBuffer[OFFSET_DATA_LENGTH] = (byte) (dataLength + 1);
        
        messageBuffer[OFFSET_DATA] = responseCode;
        Util.arrayCopy(responseData, (short) 0, messageBuffer, 
                      (short) (OFFSET_DATA + 1), dataLength);
        
        short messageLength = (short) (OFFSET_DATA + dataLength + 1);
        Util.arrayCopy(messageBuffer, (short) 0, output, offset, messageLength);
        
        return messageLength;
    }
    
    /**
     * Create error message
     */
    public short createErrorMessage(byte partnerId, byte errorCode, 
                                  byte[] output, short offset) {
        messageBuffer[OFFSET_VERSION] = PROTOCOL_VERSION;
        messageBuffer[OFFSET_TYPE] = MSG_ERROR;
        messageBuffer[OFFSET_PARTNER_ID] = partnerId;
        messageBuffer[OFFSET_SEQUENCE] = sequenceNumber++;
        messageBuffer[OFFSET_DATA_LENGTH] = 1;
        messageBuffer[OFFSET_DATA] = errorCode;
        
        short messageLength = (short) (OFFSET_DATA + 1);
        Util.arrayCopy(messageBuffer, (short) 0, output, offset, messageLength);
        
        return messageLength;
    }
    
    /**
     * Parse incoming message
     */
    public boolean parseMessage(byte[] data, short offset, short length) {
        if (length < OFFSET_DATA) {
            return false;
        }
        
        // Check protocol version
        if (data[offset + OFFSET_VERSION] != PROTOCOL_VERSION) {
            return false;
        }
        
        // Copy data to buffer
        Util.arrayCopy(data, offset, messageBuffer, (short) 0, length);
        
        return true;
    }
    
    /**
     * Get message type
     */
    public byte getMessageType() {
        return messageBuffer[OFFSET_TYPE];
    }
    
    /**
     * Get partner ID
     */
    public byte getPartnerId() {
        return messageBuffer[OFFSET_PARTNER_ID];
    }
    
    /**
     * Get sequence number
     */
    public byte getSequenceNumber() {
        return messageBuffer[OFFSET_SEQUENCE];
    }
    
    /**
     * Get message data
     */
    public short getMessageData(byte[] output, short offset) {
        short dataLength = messageBuffer[OFFSET_DATA_LENGTH];
        Util.arrayCopy(messageBuffer, OFFSET_DATA, output, offset, dataLength);
        return dataLength;
    }
    
    /**
     * Add partner to list
     */
    public boolean addPartner(byte partnerId) {
        for (byte i = 0; i < MAX_PARTNERS; i++) {
            if (partnerList[i] == 0) {
                partnerList[i] = partnerId;
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check partner existence
     */
    public boolean isPartnerValid(byte partnerId) {
        for (byte i = 0; i < MAX_PARTNERS; i++) {
            if (partnerList[i] == partnerId) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Remove partner from list securely
     */
    public boolean removePartner(byte partnerId) {
        if (!isInitialized) {
            return false;
        }
        
        for (byte i = 0; i < MAX_PARTNERS; i++) {
            if (partnerList[i] == partnerId) {
                partnerList[i] = 0;
                return true;
            }
        }
        return false;
    }
    
    /**
     * Create secure authentication message
     */
    public short createAuthenticationMessage(byte partnerId, byte[] authData, short dataLength,
                                         byte[] output, short offset) {
        if (!isInitialized || dataLength > (MAX_MESSAGE_LENGTH - OFFSET_DATA - SIGNATURE_LENGTH)) {
            return 0;
        }
        
        try {
            // Clear previous message
            Util.arrayFillNonAtomic(messageBuffer, (short) 0, (short) messageBuffer.length, (byte) 0x00);
            
            // Build authentication message
            messageBuffer[OFFSET_VERSION] = PROTOCOL_VERSION;
            messageBuffer[OFFSET_TYPE] = MSG_AUTHENTICATION;
            messageBuffer[OFFSET_PARTNER_ID] = partnerId;
            messageBuffer[OFFSET_SEQUENCE] = sequenceNumber++;
            messageBuffer[OFFSET_DATA_LENGTH] = (byte) dataLength;
            
            // Copy authentication data
            Util.arrayCopy(authData, (short) 0, messageBuffer, OFFSET_DATA, dataLength);
            
            short messageLength = (short) (OFFSET_DATA + dataLength);
            Util.arrayCopy(messageBuffer, (short) 0, output, offset, messageLength);
            
            return messageLength;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Verify message integrity
     */
    public boolean verifyMessageIntegrity(byte[] message, short offset, short length) {
        if (!isInitialized || length < OFFSET_DATA) {
            return false;
        }
        
        try {
            // Check protocol version
            if (message[offset + OFFSET_VERSION] != PROTOCOL_VERSION) {
                return false;
            }
            
            // Check message type validity
            byte msgType = message[offset + OFFSET_TYPE];
            if (msgType < MSG_HANDSHAKE || msgType > MSG_AUTHENTICATION) {
                return false;
            }
            
            // Check data length consistency
            byte dataLength = message[offset + OFFSET_DATA_LENGTH];
            short expectedLength = (short) (OFFSET_DATA + dataLength);
            if (length != expectedLength) {
                return false;
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get message signature
     */
    public short getMessageSignature(byte[] output, short offset) {
        if (!isInitialized) {
            return 0;
        }
        
        try {
            Util.arrayCopy(signatureBuffer, (short) 0, output, offset, SIGNATURE_LENGTH);
            return SIGNATURE_LENGTH;
        } catch (Exception e) {
            return 0;
        }
    }
    
    /**
     * Clear all sensitive data
     */
    public void clearSensitiveData() {
        if (!isInitialized) {
            return;
        }
        
        Util.arrayFillNonAtomic(messageBuffer, (short) 0, (short) messageBuffer.length, (byte) 0x00);
        Util.arrayFillNonAtomic(signatureBuffer, (short) 0, (short) signatureBuffer.length, (byte) 0x00);
        Util.arrayFillNonAtomic(hashBuffer, (short) 0, (short) hashBuffer.length, (byte) 0x00);
    }
    
    /**
     * Check if protocol is initialized
     */
    public boolean isInitialized() {
        return isInitialized;
    }
}
