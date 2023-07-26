/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_TSL_CA8;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;

import de.gematik.pki.gemlibpki.utils.TestUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslValidatorTest {

  @Test
  void nonNullCheck() {
    final Document nullTslDoc = null;
    assertNonNullParameter(
        () -> TslValidator.checkSignature(nullTslDoc, VALID_ISSUER_CERT_TSL_CA8), "tsl");

    final byte[] nullTslBytes = null;
    assertNonNullParameter(
        () -> TslValidator.checkSignature(nullTslBytes, VALID_ISSUER_CERT_TSL_CA8), "tsl");

    assertNonNullParameter(() -> TslValidator.checkSignature(new byte[] {0}, null), "trustAnchor");

    final Document tslAsDoc = TestUtils.getDefaultTslAsDoc();
    assertNonNullParameter(() -> TslValidator.checkSignature(tslAsDoc, null), "trustAnchor");
  }
}
