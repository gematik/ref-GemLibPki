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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getFilePathFromResources;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslReaderTest {

  TrustStatusListType tslUnsigned;

  @BeforeEach
  void setup() {
    tslUnsigned = TestUtils.getDefaultTslUnsigned();
  }

  @Test
  void verifyGetTrustStatusListTypeIsPresent() {
    assertThat(
            TslReader.getTslUnsigned(
                getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT, getClass())))
        .isNotNull();
  }

  @Test
  void getSequenceNumber() {
    assertThat(TslReader.getTslSeqNr(tslUnsigned)).isEqualTo(60);
  }

  @Test
  void getNextUpdate() {
    assertThat(TslReader.getNextUpdate(tslUnsigned)).isNotNull();
  }

  @Test
  void getNextUpdateIsNull() {
    tslUnsigned.getSchemeInformation().setNextUpdate(null);
    assertThatThrownBy(() -> TslReader.getNextUpdate(tslUnsigned))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("NextUpdate not found in TSL.");
  }

  @Test
  void getIssueDate() {
    assertThat(TslReader.getIssueDate(tslUnsigned)).isNotNull();
  }

  @Test
  void getTslDownloadUrlPrimary() {
    assertThat(TslReader.getTslDownloadUrlPrimary(tslUnsigned))
        .isEqualTo("http://127.0.0.1:8084/tsl/tsl.xml?activeTslSeqNr=60");
  }

  @Test
  void getTslDownloadUrlBackup() {
    assertThat(TslReader.getTslDownloadUrlBackup(tslUnsigned))
        .isEqualTo("http://127.0.0.1:8084/tsl-backup/tsl.xml?activeTslSeqNr=60");
  }

  @Test
  void getOtherTslPointers() {
    final OtherTSLPointersType oTslPtr = TslReader.getOtherTslPointers(tslUnsigned);
    assertThat(oTslPtr.getOtherTSLPointer()).hasSize(2);
    assertThat(
            ((MultiLangStringType)
                    oTslPtr
                        .getOtherTSLPointer()
                        .get(0)
                        .getAdditionalInformation()
                        .getTextualInformationOrOtherInformation()
                        .get(0))
                .getLang())
        .isEqualTo("DE");
  }

  @Test
  void verifyGetTrustStatusListTypeFailed() {
    final Path tslPath =
        getFilePathFromResources("tsls/ecc/invalid/TSL_invalid_xmlMalformed_altCA.xml", getClass());
    assertThatThrownBy(() -> TslReader.getTslUnsigned(tslPath))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error reading TSL.");
  }

  @Test
  void nonNullTests() {
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
