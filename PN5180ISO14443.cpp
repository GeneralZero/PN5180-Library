// NAME: PN5180ISO14443.h
//
// DESC: ISO14443 protocol on NXP Semiconductors PN5180 module for Arduino.
//
// Copyright (c) 2019 by Dirk Carstensen. All rights reserved.
//
// This file is part of the PN5180 library for the Arduino environment.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// #define DEBUG 1

#include <Arduino.h>
#include "PN5180ISO14443.h"
#include <PN5180.h>
#include "Debug.h"

PN5180ISO14443::PN5180ISO14443(uint8_t SSpin, uint8_t BUSYpin, uint8_t RSTpin) 
              : PN5180(SSpin, BUSYpin, RSTpin) {
}

bool PN5180ISO14443::setupRF() {
  PN5180DEBUG(F("Loading RF-Configuration...\n"));
  if (loadRFConfig(0x00, 0x80)) {  // ISO14443 parameters
    PN5180DEBUG(F("done.\n"));
  }
  else return false;

  PN5180DEBUG(F("Turning ON RF field...\n"));
  if (setRF_on()) {
    PN5180DEBUG(F("done.\n"));
  }
  else return false;

  return true;
}

uint16_t PN5180ISO14443::rxBytesReceived() {
	uint32_t rxStatus;
	uint16_t len = 0;
	readRegister(RX_STATUS, &rxStatus);
	// Lower 9 bits has length
	len = (uint16_t)(rxStatus & 0x000001ff);
	return len;
}
/*
* buffer : must be 10 byte array
* buffer[0-1] is ATQA
* buffer[2] is sak
* buffer[3..6] is 4 byte UID
* buffer[7..9] is remaining 3 bytes of UID for 7 Byte UID tags
* kind : 0  we send REQA, 1 we send WUPA
*
* return value: the uid length:
* -	zero if no tag was recognized
* -	single Size UID (4 byte)
* -	double Size UID (7 byte)
* -	triple Size UID (10 byte) - not yet supported
*/
uint8_t PN5180ISO14443::activateTypeA(uint8_t *buffer, uint8_t kind) {
	uint8_t cmd[7];
	uint8_t uidLength = 0;
	// Load standard TypeA protocol
	if (!loadRFConfig(0x0, 0x80)) 
	  return 0;

	// OFF Crypto
	if (!writeRegisterWithAndMask(SYSTEM_CONFIG, 0xFFFFFFBF))
	  return 0;
	// Clear RX CRC
	if (!writeRegisterWithAndMask(CRC_RX_CONFIG, 0xFFFFFFFE))
	  return 0;
	// Clear TX CRC
	if (!writeRegisterWithAndMask(CRC_TX_CONFIG, 0xFFFFFFFE))
	  return 0;
	//Send REQA/WUPA, 7 bits in last byte
	cmd[0] = (kind == 0) ? 0x26 : 0x52;
	if (!sendData(cmd, 1, 0x07))
	  return 0;
	// READ 2 bytes ATQA into  buffer
	if (!readData(2, buffer)) 
	  return 0;
	//Send Anti collision 1, 8 bits in last byte
	cmd[0] = 0x93;
	cmd[1] = 0x20;
	if (!sendData(cmd, 2, 0x00))
	  return 0;
	//Read 5 bytes, we will store at offset 2 for later usage
	if (!readData(5, cmd+2)) 
	  return 0;
	//Enable RX CRC calculation
	if (!writeRegisterWithOrMask(CRC_RX_CONFIG, 0x01)) 
	  return 0;
	//Enable TX CRC calculation
	if (!writeRegisterWithOrMask(CRC_TX_CONFIG, 0x01)) 
	  return 0;
	//Send Select anti collision 1, the remaining bytes are already in offset 2 onwards
	cmd[0] = 0x93;
	cmd[1] = 0x70;
	if (!sendData(cmd, 7, 0x00)) 
	  return 0;
	//Read 1 byte SAK into buffer[2]
	if (!readData(1, buffer+2)) 
	  return 0;
	// Check if the tag is 4 Byte UID or 7 byte UID and requires anti collision 2
	// If Bit 3 is 0 it is 4 Byte UID
	if ((buffer[2] & 0x04) == 0) {
		// Take first 4 bytes of anti collision as UID store at offset 3 onwards. job done
		for (int i = 0; i < 4; i++) buffer[3+i] = cmd[2 + i];
		uidLength = 4;
	}
	else {
		// Take First 3 bytes of UID, Ignore first byte 88(CT)
		if (cmd[2] != 0x88)
		  return 0;
		for (int i = 0; i < 3; i++) buffer[3+i] = cmd[3 + i];
		// Clear RX CRC
		if (!writeRegisterWithAndMask(CRC_RX_CONFIG, 0xFFFFFFFE)) 
	      return 0;
		// Clear TX CRC
		if (!writeRegisterWithAndMask(CRC_TX_CONFIG, 0xFFFFFFFE)) 
	      return 0;
		// Do anti collision 2
		cmd[0] = 0x95;
		cmd[1] = 0x20;
		if (!sendData(cmd, 2, 0x00)) 
	      return 0;
		//Read 5 bytes. we will store at offset 2 for later use
		if (!readData(5, cmd+2)) 
	      return 0;
		// first 4 bytes belongs to last 4 UID bytes, we keep it.
		for (int i = 0; i < 4; i++) {
		  buffer[6 + i] = cmd[2+i];
		}
		//Enable RX CRC calculation
		if (!writeRegisterWithOrMask(CRC_RX_CONFIG, 0x01)) 
	      return 0;
		//Enable TX CRC calculation
		if (!writeRegisterWithOrMask(CRC_TX_CONFIG, 0x01)) 
	      return 0;
		//Send Select anti collision 2 
		cmd[0] = 0x95;
		cmd[1] = 0x70;
		if (!sendData(cmd, 7, 0x00)) 
	      return 0;
		//Read 1 byte SAK into buffer[2]
		if (!readData(1, buffer + 2)) 
	      return 0;	
		uidLength = 7;
	}
    return uidLength;
}

bool PN5180ISO14443::mifareBlockRead(uint8_t blockno, uint8_t *buffer) {
	bool success = false;
	uint16_t len;
	uint8_t cmd[2];
	// Send mifare command 30,blockno
	cmd[0] = 0x30;
	cmd[1] = blockno;
	if (!sendData(cmd, 2, 0x00))
	  return false;
	//Check if we have received any data from the tag
	delay(5);
	len = rxBytesReceived();
	if (len == 16) {
		// READ 16 bytes into  buffer
		if (readData(16, buffer))
		  success = true;
	}
	return success;
}


uint8_t PN5180ISO14443::mifareBlockWrite16(uint8_t blockno, uint8_t *buffer) {
	uint8_t cmd[1];
	// Clear RX CRC
	writeRegisterWithAndMask(CRC_RX_CONFIG, 0xFFFFFFFE);

	// Mifare write part 1
	cmd[0] = 0xA0;
	cmd[1] = blockno;
	sendData(cmd, 2, 0x00);
	readData(1, cmd);

	// Mifare write part 2
	sendData(buffer,16, 0x00);
	delay(10);

	// Read ACK/NAK
	readData(1, cmd);

	//Enable RX CRC calculation
	writeRegisterWithOrMask(CRC_RX_CONFIG, 0x1);
	return cmd[0];
}

bool PN5180ISO14443::mifareHalt() {
	uint8_t cmd[1];
	//mifare Halt
	cmd[0] = 0x50;
	cmd[1] = 0x00;
	sendData(cmd, 2, 0x00);	
	return true;
}

uint8_t PN5180ISO14443::readCardSerial(uint8_t *buffer) {
  
    uint8_t response[10];
	uint8_t uidLength;
	// Always return 10 bytes
    // Offset 0..1 is ATQA
    // Offset 2 is SAK.
    // UID 4 bytes : offset 3 to 6 is UID, offset 7 to 9 to Zero
    // UID 7 bytes : offset 3 to 9 is UID
    for (int i = 0; i < 10; i++) response[i] = 0;
    uidLength = activateTypeA(response, 1);
	if ((response[0] == 0xFF) && (response[1] == 0xFF))
	  return 0;
	// check for valid uid
	if ((response[3] == 0x00) && (response[4] == 0x00) && (response[5] == 0x00) && (response[6] == 0x00))
	  return 0;
	if ((response[3] == 0xFF) && (response[4] == 0xFF) && (response[5] == 0xFF) && (response[6] == 0xFF))
	  return 0;
    for (int i = 0; i < 7; i++) buffer[i] = response[i+3];
	mifareHalt();
	return uidLength;  
}

bool PN5180ISO14443::isCardPresent() {
    uint8_t buffer[10];
	return (readCardSerial(buffer) >=4);
}

// Mifare Classic Authentication with Key A using PN5180 hardware command
bool PN5180ISO14443::mifareAuthenticateKeyA(uint8_t block, uint8_t *key, uint8_t *uid) {
    // Clear any existing errors first
    clearIRQStatus(0xFFFFFFFF);
    delay(10);

    // First ensure card is properly selected
    uint8_t buffer[10];
    uint8_t uidLength = activateTypeA(buffer, 1);  // WUPA to wake card
    if (uidLength == 0) {
        // Try REQA (0x26) instead of WUPA (0x52)
        uidLength = activateTypeA(buffer, 0);
        if (uidLength == 0) {
            return false;
        }
    }

    // Use fresh UID from activation
    uint8_t freshUid[4];
    for (int i = 0; i < 4; i++) {
        freshUid[i] = buffer[3 + i];
    }

    // The PN5180 hardware authentication command handles everything
    return mifareAuthenticate(key, 0x60, block, freshUid);
}

// Mifare Classic Authentication with Key B using PN5180 hardware command
bool PN5180ISO14443::mifareAuthenticateKeyB(uint8_t block, uint8_t *key, uint8_t *uid) {
    // First ensure card is properly selected
    uint8_t buffer[10];
    uint8_t uidLength = activateTypeA(buffer, 1);  // WUPA to wake card
    if (uidLength == 0) {
        return false;
    }

    // Use fresh UID from activation
    uint8_t freshUid[4];
    for (int i = 0; i < 4; i++) {
        freshUid[i] = buffer[3 + i];
    }

    // The PN5180 hardware authentication command handles everything
    return mifareAuthenticate(key, 0x61, block, freshUid);
}

// Combined authenticate and read function
bool PN5180ISO14443::mifareAuthenticatedBlockRead(uint8_t blockno, uint8_t *buffer, uint8_t *key, uint8_t *uid, bool useKeyB) {
    // Authenticate the sector containing this block
    uint8_t sector = blockno / 4;
    uint8_t authBlock = sector * 4; // First block of sector

    bool authSuccess;
    if (useKeyB) {
        authSuccess = mifareAuthenticateKeyB(authBlock, key, uid);
    } else {
        authSuccess = mifareAuthenticateKeyA(authBlock, key, uid);
    }

    if (!authSuccess) {
        return false;
    }

    // Now read the block
    return mifareBlockRead(blockno, buffer);
}

// Enhanced authenticated block read with better error handling and debugging
bool PN5180ISO14443::tryAuthenticatedBlockRead(uint8_t blockno, uint8_t *buffer, uint8_t* key, uint8_t* uid, bool useKeyB) {
    Serial.print("Attempting authenticated read of block ");
    Serial.print(blockno);
    Serial.println(":");

    // Authenticate the sector containing this block
    uint8_t sector = blockno / 4;
    uint8_t authBlock = sector * 4;  // First block of sector

    if (!mifareAuthWithFallback(authBlock, key, uid, useKeyB)) {
        return false;
    }

    // Now try to read the block
    Serial.print("Reading block ");
    Serial.print(blockno);
    Serial.print("...");

    uint8_t cmd[2];
    cmd[0] = 0x30;  // READ command
    cmd[1] = blockno;

    if (!sendData(cmd, 2, 0x00)) {
        Serial.println(" Read command failed");
        return false;
    }

    delay(10);

    uint32_t rxStatus;
    readRegister(RX_STATUS, &rxStatus);
    uint16_t len = (uint16_t)(rxStatus & 0x000001ff);

    Serial.print(" Got ");
    Serial.print(len);
    Serial.print(" bytes");

    if (len >= 16) {
        if (readData(16, buffer)) {
            Serial.println(" SUCCESS!");
            return true;
        }
    }

    Serial.println(" FAILED");
    return false;
}

// Mifare authentication with fallback mechanisms
bool PN5180ISO14443::mifareAuthWithFallback(uint8_t block, uint8_t* key, uint8_t* uid, bool useKeyB) {
    Serial.print("  Authenticating block ");
    Serial.print(block);
    Serial.print(useKeyB ? " with key B..." : " with key A...");

    // Clear any existing errors first
    clearIRQStatus(0xFFFFFFFF);
    delay(10);

    // First ensure card is properly selected
    uint8_t buffer[10];
    uint8_t uidLength = activateTypeA(buffer, 1);  // WUPA to wake card
    if (uidLength == 0) {
        Serial.println(" Card activation failed - trying REQA instead of WUPA");
        // Try REQA (0x26) instead of WUPA (0x52)
        uidLength = activateTypeA(buffer, 0);
        if (uidLength == 0) {
            Serial.println(" REQA also failed");
            return false;
        }
    }

    // Use fresh UID from activation
    uint8_t freshUid[4];
    for (int i = 0; i < 4; i++) {
        freshUid[i] = buffer[3 + i];
    }

    // Try authentication
    bool result;
    if (useKeyB) {
        result = mifareAuthenticate(key, 0x61, block, freshUid);
    } else {
        result = mifareAuthenticate(key, 0x60, block, freshUid);
    }

    Serial.println(result ? " SUCCESS" : " FAILED");
    return result;
}

// Comprehensive Mifare Classic 1K scanner
bool PN5180ISO14443::scanMifareClassic1K(uint8_t* uid, uint8_t* key) {
    Serial.println("=== MIFARE CLASSIC 1K SCAN ===");
    Serial.printf("Card UID: %02X:%02X:%02X:%02X\n", uid[0], uid[1], uid[2], uid[3]);
    Serial.println();

    // Default keys to try if none provided
    uint8_t defaultKeyA[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t ndefKey[] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};
    uint8_t transportKey[] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};

    uint8_t blockData[16];
    bool foundSomeData = false;

    // Scan all 16 sectors
    for (int sector = 0; sector < 16; sector++) {
        uint8_t firstBlock = sector * 4;
        Serial.printf("Sector %d (blocks %d-%d):\n", sector, firstBlock, firstBlock + 3);

        uint8_t* testKey = key ? key : defaultKeyA;  // Use provided key or default
        bool sectorAuthenticated = false;

        // Try different keys
        uint8_t* keys[] = {testKey, ndefKey, transportKey};
        const char* keyNames[] = {"Provided/Default", "NDEF", "Transport"};

        for (int keyIdx = 0; keyIdx < 3; keyIdx++) {
            Serial.printf("  Trying %s Key A: ", keyNames[keyIdx]);
            if (mifareAuthenticateKeyA(firstBlock, keys[keyIdx], uid)) {
                Serial.println("SUCCESS!");
                sectorAuthenticated = true;

                // Read all blocks in this sector
                for (int blockOffset = 0; blockOffset < 4; blockOffset++) {
                    uint8_t blockNum = firstBlock + blockOffset;
                    if (mifareBlockRead(blockNum, blockData)) {
                        Serial.printf("    Block %2d: ", blockNum);
                        for (int i = 0; i < 16; i++) {
                            if (blockData[i] < 0x10) Serial.print("0");
                            Serial.print(blockData[i], HEX);
                            Serial.print(" ");
                        }
                        Serial.println();
                        foundSomeData = true;
                    }
                }
                break;  // Found working key, move to next sector
            } else {
                Serial.println("Failed");
            }
        }

        if (!sectorAuthenticated) {
            Serial.println("  No working keys found for this sector");
        }
        Serial.println();
    }

    return foundSomeData;
}
