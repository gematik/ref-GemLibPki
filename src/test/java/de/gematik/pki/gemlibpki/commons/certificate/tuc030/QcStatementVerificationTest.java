/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.commons.certificate.tuc030;

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.TestConstantsNonQes;
import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import org.junit.jupiter.api.Test;

class QcStatementVerificationTest {

  @Test
  void readQcStatements_whenCertificateContainsQcStatements_thenDoesNotThrow() {
    assertDoesNotThrow(() -> QcStatementVerification.readQcStatements(VALID_X509_EE_CERT_QES));
  }

  @Test
  void readQcStatements_whenCertificateContainsNoQcStatements_thenReturnsEmptyList() {
    assertThat(
            QcStatementVerification.readQcStatements(TestConstantsNonQes.VALID_X509_EE_CERT_SMCB)
                .isEmpty())
        .isTrue();
  }

  @Test
  void checkQcStatementPresent_whenCertificateContainsQcStatement_thenDoesNotThrow() {
    assertDoesNotThrow(
        () ->
            QcStatementVerification.checkQcStatementPresent(PRODUCT_TYPE, VALID_X509_EE_CERT_QES));
  }

  @Test
  void checkQcStatementPresent_whenCertificateContainsNoQcStatement_thenThrowsGemPkiException() {
    assertThatThrownBy(
            () ->
                QcStatementVerification.checkQcStatementPresent(
                    PRODUCT_TYPE, TestConstantsNonQes.VALID_X509_EE_CERT_SMCB))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.TE_1048_QC_STATEMENT_ERROR.getErrorMessage(PRODUCT_TYPE));
  }
}
