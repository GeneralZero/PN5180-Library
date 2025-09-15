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
#ifndef PN5180ISO14443_H
#define PN5180ISO14443_H

#include "PN5180.h"

class PN5180ISO14443 : public PN5180 {

public:
  PN5180ISO14443(uint8_t SSpin, uint8_t BUSYpin, uint8_t RSTpin);
  
private:
  uint16_t rxBytesReceived();
public:
  // Mifare TypeA
  uint8_t activateTypeA(uint8_t *buffer, uint8_t kind);
  bool mifareBlockRead(uint8_t blockno,uint8_t *buffer);
  uint8_t mifareBlockWrite16(uint8_t blockno, uint8_t *buffer);
  bool mifareHalt();
  // Mifare Classic Authentication
  bool mifareAuthenticateKeyA(uint8_t block, uint8_t *key, uint8_t *uid);
  bool mifareAuthenticateKeyB(uint8_t block, uint8_t *key, uint8_t *uid);
  bool mifareAuthenticatedBlockRead(uint8_t blockno, uint8_t *buffer, uint8_t *key, uint8_t *uid, bool useKeyB = false);
  
  // Additional Mifare Classic utility functions
  bool tryAuthenticatedBlockRead(uint8_t blockno, uint8_t *buffer, uint8_t* key, uint8_t* uid, bool useKeyB = false);
  bool mifareAuthWithFallback(uint8_t block, uint8_t* key, uint8_t* uid, bool useKeyB = false);
  bool scanMifareClassic1K(uint8_t* uid, uint8_t* key = nullptr);
  /*
   * Helper functions
   */
public:   
  bool setupRF();
  uint8_t readCardSerial(uint8_t *buffer);    
  bool isCardPresent();    
};

#endif /* PN5180ISO14443_H */
