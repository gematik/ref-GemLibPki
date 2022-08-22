/*
 * Copyright (c) 2022 gematik GmbH
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

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.GEMATIK_TEST_TSP_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.time.Month;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Scanner;
import javax.xml.datatype.DatatypeConfigurationException;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslModifierTest {

  TrustStatusListType tsl;

  @BeforeEach
  void setup() {
    tsl = TestUtils.getTsl(FILE_NAME_TSL_ECC_DEFAULT);
  }

  @Test
  void modifyAllSspsOfOneTsp() throws IOException {
    final Path destFilePath = Path.of("target/TSL-test_modifiedSsp.xml");
    final int modifiedSspAmountexpected = 29;
    final String newSsp = "http://my.new-service-supply-point:8080/ocsp";
    final String newSspElement = "<ServiceSupplyPoint>" + newSsp + "</ServiceSupplyPoint>";

    TslModifier.modifySspForCAsOfTsp(tsl, GEMATIK_TEST_TSP_NAME, newSsp);
    final TslInformationProvider tslInformationProvider = new TslInformationProvider(tsl);

    // get sample and compare
    final int sampleTspServiceIdx = 0;
    final int sampleSspIdx = 0;

    assertThat(
            tslInformationProvider
                .getTspServicesForTsp(GEMATIK_TEST_TSP_NAME, TslConstants.STI_CA_LIST)
                .get(sampleTspServiceIdx)
                .getTspServiceType()
                .getServiceInformation()
                .getServiceSupplyPoints()
                .getServiceSupplyPoint()
                .get(sampleSspIdx)
                .getValue())
        .isEqualTo(newSsp);

    TslWriter.write(tsl, destFilePath);
    assertThat(countStringInFile(destFilePath, newSspElement)).isEqualTo(modifiedSspAmountexpected);
  }

  @Test
  void modifySequenceNr() {
    final Path destFileName = Path.of("target/TSL-test_modifiedSequenceNr.xml");
    final int newSequenceNr = 4732;
    TslModifier.modifySequenceNr(tsl, newSequenceNr);
    TslWriter.write(tsl, destFileName);
    assertThat(tsl.getSchemeInformation().getTSLSequenceNumber())
        .isEqualTo(BigInteger.valueOf(newSequenceNr));
  }

  @Test
  void modifyNextUpdate() throws DatatypeConfigurationException {
    final Path path = Path.of("target/TSL-test_modifiedNextUpdate.xml");
    // 2028-12-24T17:30:00

    // 2028-12-24T17:30:00Z
    final ZonedDateTime nextUpdateZdtUtc =
        ZonedDateTime.of(2028, Month.DECEMBER.getValue(), 24, 17, 30, 0, 0, ZoneOffset.UTC);

    TslModifier.modifyNextUpdate(tsl, nextUpdateZdtUtc);
    TslWriter.write(tsl, path);
    assertThat(TslReader.getNextUpdate(tsl)).isEqualTo(nextUpdateZdtUtc);
  }

  @Test
  void modifyIssueDate() throws DatatypeConfigurationException {
    final Path path = Path.of("target/TSL-test_modifiedIssueDate.xml");
    final ZonedDateTime issueDateZdUtc =
        ZonedDateTime.of(2027, Month.APRIL.getValue(), 30, 3, 42, 0, 0, ZoneOffset.UTC);

    TslModifier.modifyIssueDate(tsl, issueDateZdUtc);
    TslWriter.write(tsl, path);
    assertThat(TslReader.getIssueDate(tsl)).isEqualTo(issueDateZdUtc);
  }

  @Test
  void setNextUpdateToNextMonthAfterIssueDate() throws DatatypeConfigurationException {
    final Path path = Path.of("target/TSL-test_modifiedIssueDateAndNextUpdate.xml");
    final ZonedDateTime issueDateZdUtc = ZonedDateTime.parse("2030-04-22T10:00:00Z");

    TslModifier.modifyIssueDateAndRelatedNextUpdate(tsl, issueDateZdUtc, 30);
    TslWriter.write(tsl, path);
    assertThat(TslReader.getIssueDate(tsl)).isEqualTo(issueDateZdUtc);
    final ZonedDateTime nextUpdate = TslReader.getNextUpdate(tsl);
    assertThat(nextUpdate.getMonth()).isEqualTo(Month.MAY);
    assertThat(nextUpdate.toInstant()).hasToString("2030-05-22T10:00:00Z");
  }

  @Test
  void modifyTslDownloadUrls() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrls.xml");
    final String tslDnlUrlPrimary = "http://download-primary/myNewTsl.xml";
    final String tslDnlUrlBackup = "http://download-backup/myNewTsl.xml";
    TslModifier.setOtherTSLPointers(
        tsl,
        Map.of(
            TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY,
            tslDnlUrlPrimary,
            TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP,
            tslDnlUrlBackup));
    TslWriter.write(tsl, path);

    assertThat(TslReader.getTslDownloadUrlPrimary(tsl)).isEqualTo(tslDnlUrlPrimary);
    assertThat(TslReader.getTslDownloadUrlBackup(tsl)).isEqualTo(tslDnlUrlBackup);
  }

  /**
   * Actually a test of TslModifier and TslReader. TslModifier writes a non gematik oid, TslReader
   * cannot work with such a TSL.
   */
  @Test
  void modifyTslDownloadUrlsUnknownOidBackup() {
    final Path destFilePath = Path.of("target/TSL-test_modifiedTslDownloadUrls.xml");
    final String tslDnlUrlPrimary = "http://download-primary/myNewTsl.xml";
    final String tslDnlUrlBackup = "http://download-backup/myNewTsl.xml";
    TslModifier.setOtherTSLPointers(
        tsl,
        Map.of(
            TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY,
            tslDnlUrlPrimary,
            TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP + ".00",
            tslDnlUrlBackup));
    TslWriter.write(tsl, destFilePath);

    assertThat(TslReader.getTslDownloadUrlPrimary(tsl)).isEqualTo(tslDnlUrlPrimary);
    assertThatThrownBy(() -> TslReader.getTslDownloadUrlBackup(tsl))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP);
  }

  @Test
  void modifyTslDownloadUrlPrimary() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrlPrimary.xml");
    final String tslDnlUrlPrimary = "http://download-primary-only/myNewTsl.xml";

    TslModifier.modifyTslDownloadUrlPrimary(tsl, tslDnlUrlPrimary);
    TslWriter.write(tsl, path);

    assertThat(TslReader.getTslDownloadUrlPrimary(tsl)).isEqualTo(tslDnlUrlPrimary);
  }

  @Test
  void modifyTslDownloadUrlbackup() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrlBackup.xml");
    final String tslDnlUrlBackup = "http://download-backup-only/myNewTsl.xml";

    TslModifier.modifyTslDownloadUrlBackup(tsl, tslDnlUrlBackup);
    TslWriter.write(tsl, path);

    assertThat(TslReader.getTslDownloadUrlBackup(tsl)).isEqualTo(tslDnlUrlBackup);
  }

  private static int countStringInFile(@NonNull final Path path, @NonNull final String expected)
      throws IOException {
    final Scanner scanner = new Scanner(path);
    int cnt = 0;
    while (scanner.hasNextLine()) {
      final String line = scanner.nextLine();
      cnt += StringUtils.countMatches(line, expected);
    }
    return cnt;
  }

  @Test
  void generateTslId() {
    final ZonedDateTime issueDateZdUtc = ZonedDateTime.parse("2027-07-21T11:00:00Z");
    assertThat(TslModifier.generateTslId(42, issueDateZdUtc)).isEqualTo("ID34220270721110000Z");
  }

  @Test
  void nonNullTests() {
    AssertionsForClassTypes.assertThatThrownBy(
            () ->
                TslModifier.modifySspForCAsOfTsp(
                    null, "gematik", "http://my.new-service-supply-point:8080/ocsp"))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () ->
                TslModifier.modifySspForCAsOfTsp(
                    tsl, null, "http://my.new-service-supply-point:8080/ocsp"))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tspName is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifySspForCAsOfTsp(tsl, "gematik", null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("newSsp is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(() -> TslModifier.modifySequenceNr(null, 42))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifyNextUpdate(null, ZonedDateTime.now()))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(() -> TslModifier.modifyNextUpdate(tsl, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("zdt is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(() -> TslModifier.generateTslId(42, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("issueDate is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () ->
                TslModifier.setOtherTSLPointers(
                    null,
                    Map.of(
                        TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY,
                        "foo",
                        TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP,
                        "bar")))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(() -> TslModifier.setOtherTSLPointers(tsl, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tslPointerValues is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifyTslDownloadUrlPrimary(null, "foo"))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifyTslDownloadUrlPrimary(tsl, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("url is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifyTslDownloadUrlBackup(null, "foo"))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifyTslDownloadUrlBackup(tsl, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("url is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifyIssueDate(null, ZonedDateTime.now()))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(() -> TslModifier.modifyIssueDate(tsl, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("zdt is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifyIssueDateAndRelatedNextUpdate(null, ZonedDateTime.now(), 42))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");

    AssertionsForClassTypes.assertThatThrownBy(
            () -> TslModifier.modifyIssueDateAndRelatedNextUpdate(tsl, null, 42))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("issueDate is marked non-null but is null");
  }
}