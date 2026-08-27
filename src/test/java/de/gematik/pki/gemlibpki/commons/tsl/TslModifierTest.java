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

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.FILE_NAME_TSL_DEFAULT_NON_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.GEMATIK_TEST_TSP_NAME;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.INVALID_EXTENSION_NOT_CRIT_CERT;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.tsl.TslSignerNonQesTest.SIGNER_PATH_NON_QES;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.readP12nonQes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.tsl.TslConverter.DocToBytesOption;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.utils.P12Container;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Month;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.w3c.dom.Document;

class TslModifierTest {

  private TrustStatusListType tslUnsignedNonQes;
  private TrustStatusListType tslUnsignedQes;

  @BeforeEach
  void setup() {

    tslUnsignedNonQes = TestUtils.getDefaultTslUnsignedNonQes();
    tslUnsignedQes = TestUtils.getDefaultTslUnsignedQes();
  }

  @Test
  void
      deleteSspsForCAsOfEndEntity_whenNonQesBytesAndMatchingEndEntityAreProvided_thenRemovesServiceSupplyPoints()
          throws GemPkiException {

    final X509Certificate eeCert = VALID_X509_EE_CERT_SMCB;

    final byte[] tslBytes =
        TslModifier.deleteSspsForCAsOfEndEntity(
            TslConverter.tslUnsignedToBytes(tslUnsignedNonQes), eeCert, PRODUCT_TYPE);
    final TspService tspService =
        new TspInformationProvider(
                new TslInformationProvider(TslConverter.bytesToTslUnsigned(tslBytes))
                    .getTspServices(),
                PRODUCT_TYPE)
            .getIssuerTspService(eeCert);

    assertThat(tspService.getTspServiceType().getServiceInformation().getServiceSupplyPoints())
        .isNull();
  }

  @Test
  void
      deleteSspsForCAsOfEndEntity_whenNonQesTslAndMatchingEndEntityAreProvided_thenRemovesServiceSupplyPoints()
          throws GemPkiException {

    final X509Certificate eeCert = VALID_X509_EE_CERT_SMCB;

    TslModifier.deleteSspsForCAsOfEndEntity(tslUnsignedNonQes, eeCert, PRODUCT_TYPE);
    final TspService tspService =
        new TspInformationProvider(
                new TslInformationProvider(tslUnsignedNonQes).getTspServices(), PRODUCT_TYPE)
            .getIssuerTspService(eeCert);

    assertThat(tspService.getTspServiceType().getServiceInformation().getServiceSupplyPoints())
        .isNull();
  }

  @Test
  void modifySspForCAsOfTsp_whenMatchingTspIsProvided_thenReplacesAllServiceSupplyPoints()
      throws IOException {
    final Path destFilePath = Path.of("target/TSL-test_modifiedSsp.xml");
    final int modifiedSspAmountExpected = 21;
    final String newSsp = "http://my.new-service-supply-point:8080/ocsp";
    final String newSspElement = "<ServiceSupplyPoint>" + newSsp + "</ServiceSupplyPoint>";

    TslModifier.modifySspForCAsOfTsp(tslUnsignedNonQes, GEMATIK_TEST_TSP_NAME, newSsp);
    final TslInformationProvider tslInformationProvider =
        new TslInformationProvider(tslUnsignedNonQes);

    // get sample and compare
    assertThat(
            tslInformationProvider
                .getTspServicesForTsp(GEMATIK_TEST_TSP_NAME, TslConstants.STI_CA_LIST)
                .getFirst()
                .getTspServiceType()
                .getServiceInformation()
                .getServiceSupplyPoints()
                .getServiceSupplyPoint()
                .getFirst()
                .getValue())
        .isEqualTo(newSsp);

    TslWriter.writeUnsigned(tslUnsignedNonQes, destFilePath);
    assertThat(countStringInFile(destFilePath, newSspElement)).isEqualTo(modifiedSspAmountExpected);
  }

  @Test
  void modifySequenceNr_whenNonQesTslIsProvided_thenUpdatesSequenceNumber() {
    final Path destFileName = Path.of("target/TSL-test_modifiedSequenceNr_nonQES.xml");
    final int newTslSeqNr = 4732;
    TslModifier.modifySequenceNr(tslUnsignedNonQes, newTslSeqNr);
    TslWriter.writeUnsigned(tslUnsignedNonQes, destFileName);
    assertThat(tslUnsignedNonQes.getSchemeInformation().getTSLSequenceNumber())
        .isEqualTo(BigInteger.valueOf(newTslSeqNr));
  }

  @Test
  void modifySequenceNr_whenQesTslIsProvided_thenUpdatesSequenceNumber() {
    final Path destFileName = Path.of("target/TSL-test_modifiedSequenceNr_QES.xml");
    final int newTslSeqNr = 4732;

    TslModifier.modifySequenceNr(tslUnsignedQes, newTslSeqNr);
    TslWriter.writeUnsigned(tslUnsignedQes, destFileName);
    assertThat(tslUnsignedQes.getSchemeInformation().getTSLSequenceNumber())
        .isEqualTo(BigInteger.valueOf(newTslSeqNr));
  }

  @Test
  void modifyNextUpdate_whenNonQesTslIsProvided_thenUpdatesNextUpdate() {
    final Path path = Path.of("target/TSL-test_modifiedNextUpdate_nonQES.xml");
    // 2028-12-24T17:30:00

    // 2028-12-24T17:30:00Z
    final ZonedDateTime nextUpdateZdtUtc =
        ZonedDateTime.of(2028, Month.DECEMBER.getValue(), 24, 17, 30, 0, 0, ZoneOffset.UTC);

    TslModifier.modifyNextUpdate(tslUnsignedNonQes, nextUpdateZdtUtc);
    TslWriter.writeUnsigned(tslUnsignedNonQes, path);
    assertThat(TslReader.getNextUpdate(tslUnsignedNonQes)).isEqualTo(nextUpdateZdtUtc);
  }

  @Test
  void modifyNextUpdate_whenQesTslIsProvided_thenUpdatesNextUpdate() {
    final Path path = Path.of("target/TSL-test_modifiedNextUpdate_QES.xml");
    // 2028-12-24T17:30:00

    // 2028-12-24T17:30:00Z
    final ZonedDateTime nextUpdateZdtUtc =
        ZonedDateTime.of(2028, Month.DECEMBER.getValue(), 24, 17, 30, 0, 0, ZoneOffset.UTC);

    TslModifier.modifyNextUpdate(tslUnsignedQes, nextUpdateZdtUtc);
    TslWriter.writeUnsigned(tslUnsignedQes, path);
    assertThat(TslReader.getNextUpdate(tslUnsignedQes)).isEqualTo(nextUpdateZdtUtc);
  }

  @Test
  void modifyIssueDate_whenNonQesTslIsProvided_thenUpdatesIssueDate() {
    final Path path = Path.of("target/TSL-test_modifiedIssueDate_nonQES.xml");
    final ZonedDateTime issueDateZdUtc =
        ZonedDateTime.of(2027, Month.APRIL.getValue(), 30, 3, 42, 0, 0, ZoneOffset.UTC);

    TslModifier.modifyIssueDate(tslUnsignedNonQes, issueDateZdUtc);
    TslWriter.writeUnsigned(tslUnsignedNonQes, path);
    assertThat(TslReader.getIssueDate(tslUnsignedNonQes)).isEqualTo(issueDateZdUtc);
  }

  @Test
  void modifyIssueDate_whenQesTslIsProvided_thenUpdatesIssueDate() {
    final Path path = Path.of("target/TSL-test_modifiedIssueDate_QES.xml");
    final ZonedDateTime issueDateZdUtc =
        ZonedDateTime.of(2027, Month.APRIL.getValue(), 30, 3, 42, 0, 0, ZoneOffset.UTC);

    TslModifier.modifyIssueDate(tslUnsignedQes, issueDateZdUtc);
    TslWriter.writeUnsigned(tslUnsignedQes, path);
    assertThat(TslReader.getIssueDate(tslUnsignedQes)).isEqualTo(issueDateZdUtc);
  }

  @Test
  void
      modifyIssueDateAndRelatedNextUpdate_whenIssueDateAndMonthOffsetAreProvided_thenSetsNextUpdateOneMonthLater() {
    final Path path = Path.of("target/TSL-test_modifiedIssueDateAndNextUpdate.xml");
    final ZonedDateTime issueDateZdUtc = ZonedDateTime.parse("2030-04-22T10:00:00Z");

    TslModifier.modifyIssueDateAndRelatedNextUpdate(tslUnsignedNonQes, issueDateZdUtc, 30);
    TslWriter.writeUnsigned(tslUnsignedNonQes, path);
    assertThat(TslReader.getIssueDate(tslUnsignedNonQes)).isEqualTo(issueDateZdUtc);
    final ZonedDateTime nextUpdate = TslReader.getNextUpdate(tslUnsignedNonQes);
    assertThat(nextUpdate.getMonth()).isEqualTo(Month.MAY);
    assertThat(nextUpdate.toInstant()).hasToString("2030-05-22T10:00:00Z");
  }

  @Test
  void setOtherTSLPointers_whenPrimaryAndBackupUrlsAreProvided_thenUpdatesBothDownloadUrls() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrls.xml");
    final String tslDnlUrlPrimary = "http://download-primary/myNewTsl.xml";
    final String tslDnlUrlBackup = "http://download-backup/myNewTsl.xml";
    TslModifier.setOtherTSLPointers(
        tslUnsignedNonQes,
        Map.of(
            TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY,
            tslDnlUrlPrimary,
            TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP,
            tslDnlUrlBackup));
    TslWriter.writeUnsigned(tslUnsignedNonQes, path);

    assertThat(TslReader.getTslDownloadUrlPrimary(tslUnsignedNonQes)).isEqualTo(tslDnlUrlPrimary);
    assertThat(TslReader.getTslDownloadUrlBackup(tslUnsignedNonQes)).isEqualTo(tslDnlUrlBackup);
  }

  /**
   * Actually a test of TslModifier and TslReader. TslModifier writes a non gematik oid, TslReader
   * cannot work with such a TSL.
   */
  @Test
  void setOtherTSLPointers_whenBackupOidIsUnknown_thenPrimaryUrlIsUpdatedAndBackupLookupFails() {
    final Path destFilePath = Path.of("target/TSL-test_modifiedTslDownloadUrls.xml");
    final String tslDnlUrlPrimary = "http://download-primary/myNewTsl.xml";
    final String tslDnlUrlBackup = "http://download-backup/myNewTsl.xml";
    TslModifier.setOtherTSLPointers(
        tslUnsignedNonQes,
        Map.of(
            TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY,
            tslDnlUrlPrimary,
            TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP + ".00",
            tslDnlUrlBackup));
    TslWriter.writeUnsigned(tslUnsignedNonQes, destFilePath);

    assertThat(TslReader.getTslDownloadUrlPrimary(tslUnsignedNonQes)).isEqualTo(tslDnlUrlPrimary);
    assertThatThrownBy(() -> TslReader.getTslDownloadUrlBackup(tslUnsignedNonQes))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessageContaining(TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP);
  }

  @Test
  void modifyTslDownloadUrlPrimary_whenNewPrimaryUrlIsProvided_thenUpdatesPrimaryDownloadUrl() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrlPrimary.xml");
    final String tslDnlUrlPrimary = "http://download-primary-only/myNewTsl.xml";

    TslModifier.modifyTslDownloadUrlPrimary(tslUnsignedNonQes, tslDnlUrlPrimary);
    TslWriter.writeUnsigned(tslUnsignedNonQes, path);

    assertThat(TslReader.getTslDownloadUrlPrimary(tslUnsignedNonQes)).isEqualTo(tslDnlUrlPrimary);
  }

  @Test
  void modifyTslDownloadUrlBackup_whenNewBackupUrlIsProvided_thenUpdatesBackupDownloadUrl() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrlBackup.xml");
    final String tslDnlUrlBackup = "http://download-backup-only/myNewTsl.xml";

    TslModifier.modifyTslDownloadUrlBackup(tslUnsignedNonQes, tslDnlUrlBackup);
    TslWriter.writeUnsigned(tslUnsignedNonQes, path);

    assertThat(TslReader.getTslDownloadUrlBackup(tslUnsignedNonQes)).isEqualTo(tslDnlUrlBackup);
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
  void generateTslId_whenSequenceNumberAndIssueDateAreProvided_thenReturnsFormattedId() {
    final ZonedDateTime issueDateZdUtc = ZonedDateTime.parse("2027-07-21T11:00:00Z");
    assertThat(TslModifier.generateTslId(42, issueDateZdUtc)).isEqualTo("ID34220270721110000Z");
  }

  @Test
  void tslModifierMethods_whenCoreRequiredArgumentsAreNull_thenFailFast() {
    assertNonNullParameter(
        () ->
            TslModifier.modifySspForCAsOfTsp(
                null, "gematik", "http://my.new-service-supply-point:8080/ocsp"),
        "tsl");

    assertNonNullParameter(
        () ->
            TslModifier.modifySspForCAsOfTsp(
                tslUnsignedNonQes, null, "http://my.new-service-supply-point:8080/ocsp"),
        "tspName");

    assertNonNullParameter(
        () -> TslModifier.modifySspForCAsOfTsp(tslUnsignedNonQes, "gematik", null), "newSsp");

    assertNonNullParameter(() -> TslModifier.modifySequenceNr(null, 42), "tsl");

    assertNonNullParameter(() -> TslModifier.modifyNextUpdate(null, ZonedDateTime.now()), "tsl");

    assertNonNullParameter(() -> TslModifier.modifyNextUpdate(tslUnsignedNonQes, null), "zdt");

    assertNonNullParameter(() -> TslModifier.generateTslId(42, null), "issueDate");

    assertNonNullParameter(
        () ->
            TslModifier.setOtherTSLPointers(
                null,
                Map.of(
                    TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY,
                    "foo",
                    TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP,
                    "bar")),
        "tsl");

    assertNonNullParameter(
        () -> TslModifier.setOtherTSLPointers(tslUnsignedNonQes, null), "tslPointerValues");

    assertNonNullParameter(() -> TslModifier.modifyTslDownloadUrlPrimary(null, "foo"), "tsl");

    assertNonNullParameter(
        () -> TslModifier.modifyTslDownloadUrlPrimary(tslUnsignedNonQes, null), "url");

    assertNonNullParameter(() -> TslModifier.modifyTslDownloadUrlBackup(null, "foo"), "tsl");

    assertNonNullParameter(
        () -> TslModifier.modifyTslDownloadUrlBackup(tslUnsignedNonQes, null), "url");
    assertNonNullParameter(
        () -> TslModifier.modifySignerCert(tslUnsignedNonQes, null), "x509CertificateEncoded");
  }

  @Test
  void tslModifierMethods_whenAdditionalRequiredArgumentsAreNull_thenFailFast() {
    assertNonNullParameter(
        () -> TslModifier.modifiedStatusStartingTime(null, null, null, null, null), "tspName");
    assertNonNullParameter(
        () -> TslModifier.modifiedStatusStartingTime(null, "", null, null, null),
        "newStatusStartingTime");

    assertNonNullParameter(
        () -> TslModifier.modifyStatusStartingTime(null, null, null, null, null), "tspName");
    assertNonNullParameter(
        () -> TslModifier.modifyStatusStartingTime(null, "", null, null, null),
        "newStatusStartingTime");

    assertNonNullParameter(() -> TslModifier.modifyIssueDate(null, ZonedDateTime.now()), "tsl");

    assertNonNullParameter(() -> TslModifier.modifyIssueDate(tslUnsignedNonQes, null), "zdt");

    assertNonNullParameter(
        () -> TslModifier.modifyIssueDateAndRelatedNextUpdate(null, ZonedDateTime.now(), 42),
        "tsl");

    assertNonNullParameter(
        () -> TslModifier.modifyIssueDateAndRelatedNextUpdate(tslUnsignedNonQes, null, 42),
        "issueDate");

    final X509Certificate eeCert = VALID_X509_EE_CERT_SMCB;

    final byte[] tslBytes = new byte[0];

    assertNonNullParameter(
        () -> TslModifier.deleteSspsForCAsOfEndEntity((byte[]) null, eeCert, PRODUCT_TYPE),
        "tslBytes");

    assertNonNullParameter(
        () -> TslModifier.deleteSspsForCAsOfEndEntity(tslBytes, null, PRODUCT_TYPE), "x509EeCert");

    assertNonNullParameter(
        () -> TslModifier.deleteSspsForCAsOfEndEntity(tslBytes, eeCert, null), "productType");

    assertNonNullParameter(
        () ->
            TslModifier.deleteSspsForCAsOfEndEntity(
                (TrustStatusListType) null, eeCert, PRODUCT_TYPE),
        "tsl");

    assertNonNullParameter(
        () -> TslModifier.deleteSspsForCAsOfEndEntity(tslUnsignedNonQes, null, PRODUCT_TYPE),
        "x509EeCert");

    assertNonNullParameter(
        () -> TslModifier.deleteSspsForCAsOfEndEntity(tslUnsignedNonQes, eeCert, null),
        "productType");
  }

  private void assertSignerCertInTsl(final String tslStr, final X509Certificate signerCert) {

    String tslSignerRegexFormat =
        "<ds:KeyInfo>\\s*<ds:X509Data>\\s*<ds:X509Certificate>"
            + "\\Q%s\\E</ds:X509Certificate>\\s*</ds:X509Data>\\s*</ds:KeyInfo>";

    // namespace suffix
    tslSignerRegexFormat = tslSignerRegexFormat.replace("ds:", "[a-z0-9]+:");

    final String signerCertStr = GemLibPkiUtils.toMimeBase64NoLineBreaks(signerCert);

    final Pattern pattern = Pattern.compile(tslSignerRegexFormat.formatted(signerCertStr));
    final Matcher matcher = pattern.matcher(tslStr);

    assertThat(matcher.find()).isTrue();
    assertThat(matcher.find()).isFalse();
  }

  @Test
  void modifiedSignerCert_whenNewSignerCertificateIsProvided_thenReplacesSignerCertificate() {

    tslUnsignedNonQes = TestUtils.getTslUnsigned(FILE_NAME_TSL_DEFAULT_NON_QES);
    final X509Certificate oldSignerCert = TslUtils.getFirstTslSignerCertificate(tslUnsignedNonQes);
    final X509Certificate eeCert = INVALID_EXTENSION_NOT_CRIT_CERT;
    assertThat(oldSignerCert).isNotEqualTo(eeCert);

    final byte[] tslBytes = TslConverter.tslUnsignedToBytes(tslUnsignedNonQes);
    final byte[] tslBytesNew = TslModifier.modifiedSignerCert(tslBytes, eeCert);
    final String tslStrNew = new String(tslBytesNew, StandardCharsets.UTF_8);

    final TrustStatusListType tslNewUnsigned = TslConverter.bytesToTslUnsigned(tslBytesNew);
    final X509Certificate eeCertNew = TslUtils.getFirstTslSignerCertificate(tslNewUnsigned);

    assertThat(eeCertNew).isEqualTo(eeCert);
    assertSignerCertInTsl(tslStrNew, eeCert);
  }

  @Test
  void getXmlGregorianCalendar_whenDatatypeFactoryCreationFails_thenThrowsGemPkiRuntimeException() {
    final ZonedDateTime now = GemLibPkiUtils.now();
    try (final MockedStatic<DatatypeFactory> datatypeFactory =
        Mockito.mockStatic(DatatypeFactory.class)) {
      datatypeFactory
          .when(DatatypeFactory::newInstance)
          .thenThrow(new DatatypeConfigurationException());
      assertThatThrownBy(() -> TslModifier.getXmlGregorianCalendar(now))
          .isInstanceOf(GemPkiRuntimeException.class)
          .cause()
          .isInstanceOf(DatatypeConfigurationException.class);
    }
  }

  @Test
  void getXmlGregorianCalendar_whenArgumentIsNull_thenFailFast() {
    assertNonNullParameter(() -> TslModifier.getXmlGregorianCalendar(null), "zdt");
  }

  @Test
  void
      modifiedSignerCert_whenExistingSignerCertificateIsProvided_thenLeavesSignerCertificateUnchanged() {

    tslUnsignedNonQes = TestUtils.getTslUnsigned(FILE_NAME_TSL_DEFAULT_NON_QES);
    final X509Certificate signerCertFromTsl =
        TslUtils.getFirstTslSignerCertificate(tslUnsignedNonQes);

    final byte[] tslBytes = TslConverter.tslUnsignedToBytes(tslUnsignedNonQes);
    final byte[] tslBytesNew = TslModifier.modifiedSignerCert(tslBytes, signerCertFromTsl);
    final String tslStrNew = new String(tslBytesNew, StandardCharsets.UTF_8);

    final TrustStatusListType tslNewUnsigned = TslConverter.bytesToTslUnsigned(tslBytesNew);

    final X509Certificate signerCertNew = TslUtils.getFirstTslSignerCertificate(tslNewUnsigned);

    assertThat(signerCertNew).isEqualTo(signerCertFromTsl);

    assertSignerCertInTsl(tslStrNew, signerCertFromTsl);
  }

  @Test
  void docToBytes_whenPrettyPrintOptionIsUsed_thenReturnsFormattedXml() {
    final String xmlOneLine =
        "<note><to>email1</to><from>email2</from><heading>Reminder</heading><body>Gematik!</body></note>";
    final String xmlPrettyPrintExpected =
        """
            <note>
                <to>email1</to>
                <from>email2</from>
                <heading>Reminder</heading>
                <body>Gematik!</body>
            </note>
            """;
    assertThat(xmlOneLine).isNotEqualTo(xmlPrettyPrintExpected);

    final Document xmlDoc = TslConverter.bytesToDoc(xmlOneLine.getBytes(StandardCharsets.UTF_8));
    final byte[] xmlPrettyPrintBytes =
        TslConverter.docToBytes(xmlDoc, DocToBytesOption.PRETTY_PRINT);

    String xmlPrettyPrint = new String(xmlPrettyPrintBytes, StandardCharsets.UTF_8);
    xmlPrettyPrint = xmlPrettyPrint.replace("\r\n", "\n");

    assertThat(xmlPrettyPrint).isEqualTo(xmlPrettyPrintExpected);
  }

  @Test
  void docToBytes_whenSignedPrettyPrintedDocumentIsSerialized_thenKeepsIndentation() {

    final TslSignerNonQes.TslSignerNonQesBuilder tslSignerBuilder = TslSignerNonQes.builder();
    final P12Container signerEcc = readP12nonQes(SIGNER_PATH_NON_QES);

    final Document tslDoc = TslConverter.tslToDocUnsigned(tslUnsignedNonQes);
    final byte[] tslBytes = TslConverter.docToBytes(tslDoc);

    final String indentationIndicator = "\n ";
    assertThat(
            StringUtils.countMatches(
                new String(tslBytes, StandardCharsets.UTF_8), indentationIndicator))
        .isZero();

    tslSignerBuilder.tslToSign(tslDoc).tslSignerP12(signerEcc).build().sign();

    final byte[] signedTslBytes = TslConverter.docToBytes(tslDoc);

    // NOTE: sing() adds the signature element with few line breaks  (that are not pretty printed),
    // the original xml remains as is, in this case - a single line
    assertThat(
            StringUtils.countMatches(
                new String(signedTslBytes, StandardCharsets.UTF_8), indentationIndicator))
        .isLessThan(100);

    final Document tslDoc2 = TslConverter.bytesToDoc(tslBytes);

    final byte[] tslBytesPrettyPrinted =
        TslConverter.docToBytes(tslDoc2, DocToBytesOption.PRETTY_PRINT);
    final Document tslDocPrettyPrinted = TslConverter.bytesToDoc(tslBytesPrettyPrinted);
    tslSignerBuilder.tslToSign(tslDocPrettyPrinted).tslSignerP12(signerEcc).build().sign();

    final byte[] signedAndPrettyPrintedTslBytes = TslConverter.docToBytes(tslDocPrettyPrinted);

    final int nrOfMinIdent = 5000;

    int countIndentationIndicator =
        StringUtils.countMatches(
            new String(tslBytesPrettyPrinted, StandardCharsets.UTF_8), indentationIndicator);
    assertThat(countIndentationIndicator).isGreaterThan(nrOfMinIdent);

    countIndentationIndicator =
        StringUtils.countMatches(
            new String(signedAndPrettyPrintedTslBytes, StandardCharsets.UTF_8),
            indentationIndicator);
    assertThat(countIndentationIndicator).isGreaterThan(nrOfMinIdent);
  }

  @Test
  void modifiedTslId_whenExplicitIdIsProvided_thenUpdatesTslId() {
    final String newTslId = "newId_" + GemLibPkiUtils.now();
    final byte[] modifiedTslBytes =
        TslModifier.modifiedTslId(TslConverter.tslUnsignedToBytes(tslUnsignedNonQes), newTslId);

    final TrustStatusListType tslUnsigned = TslConverter.bytesToTslUnsigned(modifiedTslBytes);

    assertThat(tslUnsigned.getId()).isEqualTo(newTslId);
  }

  @Test
  void modifiedTslId_whenSequenceNumberAndIssueDateAreProvided_thenUpdatesTslId() {
    final ZonedDateTime issueDate = GemLibPkiUtils.now().minusYears(1);
    final int tslSeqNr = 900001;
    final String expectedTslId = TslModifier.generateTslId(tslSeqNr, issueDate);

    final byte[] modifiedTslBytes =
        TslModifier.modifiedTslId(
            TslConverter.tslUnsignedToBytes(tslUnsignedNonQes), tslSeqNr, issueDate);

    final TrustStatusListType tslUnsigned = TslConverter.bytesToTslUnsigned(modifiedTslBytes);

    assertThat(tslUnsigned.getId()).isEqualTo(expectedTslId);

    final byte[] tslBytesUnsigned = TslConverter.tslUnsignedToBytes(tslUnsigned);
    assertNonNullParameter(
        () -> TslModifier.modifiedTslId(tslBytesUnsigned, tslSeqNr, null), "issueDate");
  }

  @Test
  void modifiedTspTradeName_whenExistingTradeNameMatches_thenReplacesTradeNameOccurrences() {

    final byte[] tslBytes = TslConverter.tslUnsignedToBytes(tslUnsignedNonQes);
    final String tslStr = new String(tslBytes, StandardCharsets.UTF_8);

    final String gematikTspName = "gematik GmbH - PKI TEST TSP";
    final String gematikOldTspTradeName = "gematik Test-TSL: initialTslDownload";
    final String gematikNewTspTradeName = "gematik Test-TSL: DUMMY VALUE";

    final int countDefault = StringUtils.countMatches(tslStr, gematikOldTspTradeName);

    assertThat(countDefault).isNotZero();
    assertThat(StringUtils.countMatches(tslStr, gematikNewTspTradeName)).isZero();

    final byte[] modifiedTslBytes =
        TslModifier.modifiedTspTradeName(
            tslBytes, gematikTspName, gematikOldTspTradeName, gematikNewTspTradeName);

    final String modifiedTslStr = new String(modifiedTslBytes, StandardCharsets.UTF_8);

    assertThat(StringUtils.countMatches(modifiedTslStr, gematikOldTspTradeName)).isZero();
    assertThat(StringUtils.countMatches(modifiedTslStr, gematikNewTspTradeName))
        .isEqualTo(countDefault);
  }

  @Test
  void modifiedStatusStartingTime_whenAnnouncedTrustAnchorIsSelected_thenUpdatesStatusStartingTime()
      throws DatatypeConfigurationException {

    final TrustStatusListType oldTsl =
        TestUtils.getTslUnsigned("tsls/nonqes/valid/TSL_TAchange.xml");

    final String tspNameToSelect = "gematik GmbH - PKI TEST TSP";
    final String serviceIdentifierToSelect = TslConstants.STI_SRV_CERT_CHANGE;
    final String serviceStatusToSelect = null;

    final XMLGregorianCalendar oldStartingStatusTimeGreg =
        DatatypeFactory.newInstance().newXMLGregorianCalendar("2025-07-23T11:51:04Z");

    final ZonedDateTime newStartingStatusTime = GemLibPkiUtils.now();
    final XMLGregorianCalendar newStartingStatusTimeGreg =
        TslModifier.getXmlGregorianCalendar(newStartingStatusTime);

    final byte[] tslBytes = TslConverter.tslUnsignedToBytes(oldTsl);

    final byte[] modifiedTslBytes =
        TslModifier.modifiedStatusStartingTime(
            tslBytes,
            tspNameToSelect,
            serviceIdentifierToSelect,
            serviceStatusToSelect,
            newStartingStatusTime);

    final BiConsumer<TrustStatusListType, XMLGregorianCalendar> statusStartingTimeAsserts =
        (someTsl, startingStatusTimeGreg) -> {
          final TslInformationProvider informationProvider = new TslInformationProvider(someTsl);

          final List<TspService> tspServices =
              informationProvider.getFilteredTspServices(List.of(TslConstants.STI_SRV_CERT_CHANGE));

          assertThat(tspServices).hasSize(1);
          assertThat(
                  tspServices
                      .getFirst()
                      .getTspServiceType()
                      .getServiceInformation()
                      .getStatusStartingTime())
              .isEqualTo(startingStatusTimeGreg);
        };

    statusStartingTimeAsserts.accept(oldTsl, oldStartingStatusTimeGreg);
    statusStartingTimeAsserts.accept(
        TslConverter.bytesToTslUnsigned(modifiedTslBytes), newStartingStatusTimeGreg);
  }

  @Test
  void deleteSignature_whenTslContainsSignature_thenRemovesSignature() {

    final TrustStatusListType tsl = TestUtils.getTslUnsigned("tsls/nonqes/valid/TSL_TAchange.xml");
    assertThat(tsl.getSignature()).isNotNull();

    TslModifier.deleteSignature(tsl);
    assertThat(tsl.getSignature()).isNull();
  }

  @Test
  void modifyStatusStartingTime_whenMatchingServiceExists_thenDoesNotThrow() {

    final String gematikTspName = "gematik GmbH - PKI TEST TSP";
    final ZonedDateTime now = GemLibPkiUtils.now();
    assertDoesNotThrow(
        () ->
            TslModifier.modifyStatusStartingTime(
                tslUnsignedNonQes,
                gematikTspName,
                TslConstants.STI_PKC,
                TslConstants.SVCSTATUS_INACCORD,
                now));
  }
}
