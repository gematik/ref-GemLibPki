/*
 * Copyright 2025, gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.certificate;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/** Enum that host {@link KeyUsage} information. */
@RequiredArgsConstructor
@Getter
public enum KeyUsage {
  /**
   * KeyUsage ::= BIT STRING { digitalSignature (0), nonRepudiation (1), keyEncipherment (2),
   * dataEncipherment (3), keyAgreement (4), keyCertSign (5), cRLSign (6), encipherOnly (7),
   * decipherOnly (8) }
   */
  KEYUSAGE_DIGITAL_SIGNATURE("digitalSignature", 0),
  KEYUSAGE_NON_REPUDIATION("nonRepudiation", 1),
  KEYUSAGE_KEY_ENCIPHERMENT("keyEncipherment", 2),
  KEYUSAGE_DATA_ENCIPHERMENT("dataEncipherment", 3),
  KEYUSAGE_KEY_AGREEMENT("keyAgreement", 4),
  KEYUSAGE_CRL_SIGN("cRLSign", 6);

  private final String description;
  private final int bit;
}
