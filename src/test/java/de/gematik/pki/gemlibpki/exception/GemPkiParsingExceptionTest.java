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

package de.gematik.pki.gemlibpki.exception;

import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import java.util.EnumMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GemPkiParsingExceptionTest {
  @Test
  void apiTest() {
    final Map<CertificateProfile, GemPkiException> map = new EnumMap<>(CertificateProfile.class);
    assertThatThrownBy(() -> new GemPkiParsingException(PRODUCT_TYPE, map))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Please understand the api of this library.");
  }

  @Test
  void nonNullTests() {
    final EnumMap<CertificateProfile, GemPkiException> error =
        new EnumMap<>(CertificateProfile.class);
    error.put(
        CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC,
        new GemPkiException(PRODUCT_TYPE, ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR));

    assertThatThrownBy(() -> new GemPkiParsingException(null, error))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("productType is marked non-null but is null");

    assertThatThrownBy(() -> new GemPkiParsingException(PRODUCT_TYPE, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("Cannot invoke \"java.util.Map.values()\" because \"errorMap\" is null");
  }
}
