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

package de.gematik.pki.gemlibpki.commons.validators;

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.tsl.TslConstants;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceStatusHistoryEntry;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

class QesCaQualificationValidatorTest {

  @Test
  @SuppressWarnings("DataFlowIssue")
  void
      qesCaQualificationValidator_whenProductTypeOrQesCaTspServiceSubsetIsNull_thenThrowsNullPointerException() {
    final TspServiceSubset tspServiceSubset = TspServiceSubset.builder().build();

    assertNonNullParameter(
        () -> new QesCaQualificationValidator(null, tspServiceSubset), "productType");
    assertNonNullParameter(
        () -> new QesCaQualificationValidator(PRODUCT_TYPE, null), "qesCaTspServiceSubset");
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void validate_whenReferenceDateIsNull_thenThrowsNullPointerException() {
    final QesCaQualificationValidator tested =
        new QesCaQualificationValidator(PRODUCT_TYPE, TspServiceSubset.builder().build());

    assertNonNullParameter(() -> tested.validate(null), "referenceDate");
  }

  @Test
  void validate_whenServiceStatusIsGrantedAndStarted_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final TspServiceSubset qesCaTspServiceSubset =
        TspServiceSubset.builder()
            .serviceStatus(TslConstants.SVCSTATUS_GRANTED)
            .statusStartingTime(referenceDate.minusDays(1))
            .build();

    final QesCaQualificationValidator tested =
        new QesCaQualificationValidator(PRODUCT_TYPE, qesCaTspServiceSubset);

    assertDoesNotThrow(() -> tested.validate(referenceDate));
  }

  @Test
  void validate_whenServiceStatusStartsInFuture_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final TspServiceSubset qesCaTspServiceSubset =
        TspServiceSubset.builder()
            .serviceStatus(TslConstants.SVCSTATUS_GRANTED)
            .statusStartingTime(referenceDate.plusDays(1))
            .build();

    final QesCaQualificationValidator tested =
        new QesCaQualificationValidator(PRODUCT_TYPE, qesCaTspServiceSubset);

    assertThatThrownBy(() -> tested.validate(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(
            ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void validate_whenServiceStatusIsWithdrawnAtReferenceDate_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final TspServiceSubset qesCaTspServiceSubset =
        TspServiceSubset.builder()
            .serviceStatus(TslConstants.SVCSTATUS_WITHDRAWN)
            .statusStartingTime(referenceDate.minusDays(1))
            .build();

    final QesCaQualificationValidator tested =
        new QesCaQualificationValidator(PRODUCT_TYPE, qesCaTspServiceSubset);

    assertThatThrownBy(() -> tested.validate(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(
            ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void validate_whenWithdrawnStatusHasGrantedHistoryBeforeReferenceDate_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final TspServiceSubset qesCaTspServiceSubset =
        TspServiceSubset.builder()
            .serviceStatus(TslConstants.SVCSTATUS_WITHDRAWN)
            .statusStartingTime(referenceDate.plusDays(1))
            .serviceStatusHistory(
                List.of(
                    new TspServiceStatusHistoryEntry(
                        TslConstants.SVCSTATUS_GRANTED, referenceDate.minusDays(10))))
            .build();

    final QesCaQualificationValidator tested =
        new QesCaQualificationValidator(PRODUCT_TYPE, qesCaTspServiceSubset);

    assertDoesNotThrow(() -> tested.validate(referenceDate));
  }

  @Test
  void
      validate_whenWithdrawnStatusHasNoGrantedHistoryBeforeReferenceDate_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final TspServiceSubset qesCaTspServiceSubset =
        TspServiceSubset.builder()
            .serviceStatus(TslConstants.SVCSTATUS_WITHDRAWN)
            .statusStartingTime(referenceDate.plusDays(1))
            .build();

    final QesCaQualificationValidator tested =
        new QesCaQualificationValidator(PRODUCT_TYPE, qesCaTspServiceSubset);

    assertThatThrownBy(() -> tested.validate(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(
            ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void validate_whenServiceStatusIsMissing_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final TspServiceSubset qesCaTspServiceSubset =
        TspServiceSubset.builder().statusStartingTime(referenceDate.minusDays(1)).build();

    final QesCaQualificationValidator tested =
        new QesCaQualificationValidator(PRODUCT_TYPE, qesCaTspServiceSubset);

    assertThatThrownBy(() -> tested.validate(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(
            ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED.getErrorMessage(PRODUCT_TYPE));
  }
}
