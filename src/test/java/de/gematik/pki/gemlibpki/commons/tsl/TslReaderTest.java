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

package de.gematik.pki.gemlibpki.commons.tsl;

import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.FILE_NAME_TSL_DEFAULT_NON_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_DEFAULT_QES;
import static de.gematik.pki.gemlibpki.commons.utils.ResourceReader.getFilePathFromResources;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslReaderTest {

  TrustStatusListType tslUnsignedNonQes;
  TrustStatusListType tslUnsignedQes;

  @BeforeEach
  void setup() {

    tslUnsignedNonQes = TestUtils.getDefaultTslUnsignedNonQes();
    tslUnsignedQes = TestUtils.getDefaultTslUnsignedQes();
  }

  @Test
  void getTslUnsigned_whenNonQesTslPathIsProvided_thenReturnsTrustStatusList() {
    assertThat(
            TslReader.getTslUnsigned(
                getFilePathFromResources(FILE_NAME_TSL_DEFAULT_NON_QES, getClass())))
        .isNotNull();
  }

  @Test
  void getTslUnsigned_whenQesTslPathIsProvided_thenReturnsTrustStatusList() {
    assertThat(
            TslReader.getTslUnsigned(
                getFilePathFromResources(FILE_NAME_TSL_DEFAULT_QES, getClass())))
        .isNotNull();
  }

  @Test
  void getTslSeqNr_whenNonQesTslIsProvided_thenReturnsExpectedSequenceNumber() {
    assertThat(TslReader.getTslSeqNr(tslUnsignedNonQes)).isEqualTo(420127);
  }

  @Test
  void getTslSeqNr_whenQesTslIsProvided_thenReturnsExpectedSequenceNumber() {
    assertThat(TslReader.getTslSeqNr(tslUnsignedQes)).isEqualTo(60);
  }

  @Test
  void getNextUpdate_whenNonQesTslIsProvided_thenReturnsNextUpdate() {
    assertThat(TslReader.getNextUpdate(tslUnsignedNonQes)).isNotNull();
  }

  @Test
  void getNextUpdate_whenQesTslIsProvided_thenReturnsNextUpdate() {
    assertThat(TslReader.getNextUpdate(tslUnsignedQes)).isNotNull();
  }

  @Test
  void getNextUpdate_whenNextUpdateIsMissing_thenThrowsGemPkiRuntimeException() {
    tslUnsignedNonQes.getSchemeInformation().setNextUpdate(null);
    assertThatThrownBy(() -> TslReader.getNextUpdate(tslUnsignedNonQes))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("NextUpdate not found in TSL.");
  }

  @Test
  void getIssueDate_whenTslIsProvided_thenReturnsIssueDate() {
    assertThat(TslReader.getIssueDate(tslUnsignedNonQes)).isNotNull();
  }

  @Test
  void getTslDownloadUrlPrimary_whenNonQesTslIsProvided_thenReturnsPrimaryUrl() {
    assertThat(TslReader.getTslDownloadUrlPrimary(tslUnsignedNonQes))
        .isEqualTo("http://127.0.0.1:8084/tsl/tsl.xml?activeTslSeqNr=420127");
  }

  @Test
  void getTslDownloadUrlBackup_whenNonQesTslIsProvided_thenReturnsBackupUrl() {
    assertThat(TslReader.getTslDownloadUrlBackup(tslUnsignedNonQes))
        .isEqualTo("http://127.0.0.1:8084/tsl-backup/tsl.xml?activeTslSeqNr=420127");
  }

  @Test
  void getOtherTslPointers_whenNonQesTslIsProvided_thenReturnsExpectedPointers() {
    final OtherTSLPointersType oTslPtr = TslReader.getOtherTslPointers(tslUnsignedNonQes);
    assertThat(oTslPtr.getOtherTSLPointer()).hasSize(2);
    assertThat(
            ((MultiLangStringType)
                    oTslPtr
                        .getOtherTSLPointer()
                        .getFirst()
                        .getAdditionalInformation()
                        .getTextualInformationOrOtherInformation()
                        .getFirst())
                .getLang())
        .isEqualTo("DE");
  }

  @Test
  void getTslUnsigned_whenXmlIsMalformed_thenThrowsGemPkiRuntimeException() {
    final Path tslPath =
        getFilePathFromResources(
            "tsls/nonqes/invalid/TSL_invalid_xmlMalformed_altCA.xml", getClass());
    assertThatThrownBy(() -> TslReader.getTslUnsigned(tslPath))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error reading TSL.");
  }

  @Test
  void tslReaderMethods_whenRequiredArgumentsAreNull_thenFailFast() {
    assertNonNullParameter(() -> TslReader.getTslAsDoc(null), "tslPath");

    assertNonNullParameter(() -> TslReader.getTslUnsigned(null), "tslPath");

    assertNonNullParameter(() -> TslReader.getTslSeqNr(null), "tsl");

    assertNonNullParameter(() -> TslReader.getNextUpdate(null), "tsl");

    assertNonNullParameter(() -> TslReader.getIssueDate(null), "tsl");

    assertNonNullParameter(() -> TslReader.getOtherTslPointers(null), "tsl");

    assertNonNullParameter(() -> TslReader.getTslDownloadUrlPrimary(null), "tsl");

    assertNonNullParameter(() -> TslReader.getTslDownloadUrlBackup(null), "tsl");
  }
}
