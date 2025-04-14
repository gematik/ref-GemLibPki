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
import static de.gematik.pki.gemlibpki.TestConstants.GEMATIK_TEST_TSP_NAME;
import static de.gematik.pki.gemlibpki.TestConstants.INVALID_EXTENSION_NOT_CRIT_CERT;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.tsl.TslSignerTest.SIGNER_PATH_ECC;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.utils.TestUtils.readP12;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TslConverter.DocToBytesOption;
import de.gematik.pki.gemlibpki.tsl.TslSigner.TslSignerBuilder;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.TestUtils;
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

  private TrustStatusListType tslUnsigned;

  @BeforeEach
  void setup() {
    tslUnsigned = TestUtils.getDefaultTslUnsigned();
  }

  @Test
  void deleteAllSspsOfOneTspAsBytes() throws GemPkiException {

    final X509Certificate eeCert = VALID_X509_EE_CERT_SMCB;

    final byte[] tslBytes =
        TslModifier.deleteSspsForCAsOfEndEntity(
            TslConverter.tslUnsignedToBytes(tslUnsigned), eeCert, PRODUCT_TYPE);
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
  void deleteAllSspsOfOneTsp() throws GemPkiException {

    final X509Certificate eeCert = VALID_X509_EE_CERT_SMCB;

    TslModifier.deleteSspsForCAsOfEndEntity(tslUnsigned, eeCert, PRODUCT_TYPE);
    final TspService tspService =
        new TspInformationProvider(
                new TslInformationProvider(tslUnsigned).getTspServices(), PRODUCT_TYPE)
            .getIssuerTspService(eeCert);

    assertThat(tspService.getTspServiceType().getServiceInformation().getServiceSupplyPoints())
        .isNull();
  }

  @Test
  void modifyAllSspsOfOneTsp() throws IOException {
    final Path destFilePath = Path.of("target/TSL-test_modifiedSsp.xml");
    final int modifiedSspAmountExpected = 32;
    final String newSsp = "http://my.new-service-supply-point:8080/ocsp";
    final String newSspElement = "<ServiceSupplyPoint>" + newSsp + "</ServiceSupplyPoint>";

    TslModifier.modifySspForCAsOfTsp(tslUnsigned, GEMATIK_TEST_TSP_NAME, newSsp);
    final TslInformationProvider tslInformationProvider = new TslInformationProvider(tslUnsigned);

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

    TslWriter.writeUnsigned(tslUnsigned, destFilePath);
    assertThat(countStringInFile(destFilePath, newSspElement)).isEqualTo(modifiedSspAmountExpected);
  }

  @Test
  void modifySequenceNr() {
    final Path destFileName = Path.of("target/TSL-test_modifiedSequenceNr.xml");
    final int newTslSeqNr = 4732;
    TslModifier.modifySequenceNr(tslUnsigned, newTslSeqNr);
    TslWriter.writeUnsigned(tslUnsigned, destFileName);
    assertThat(tslUnsigned.getSchemeInformation().getTSLSequenceNumber())
        .isEqualTo(BigInteger.valueOf(newTslSeqNr));
  }

  @Test
  void modifyNextUpdate() {
    final Path path = Path.of("target/TSL-test_modifiedNextUpdate.xml");
    // 2028-12-24T17:30:00

    // 2028-12-24T17:30:00Z
    final ZonedDateTime nextUpdateZdtUtc =
        ZonedDateTime.of(2028, Month.DECEMBER.getValue(), 24, 17, 30, 0, 0, ZoneOffset.UTC);

    TslModifier.modifyNextUpdate(tslUnsigned, nextUpdateZdtUtc);
    TslWriter.writeUnsigned(tslUnsigned, path);
    assertThat(TslReader.getNextUpdate(tslUnsigned)).isEqualTo(nextUpdateZdtUtc);
  }

  @Test
  void modifyIssueDate() {
    final Path path = Path.of("target/TSL-test_modifiedIssueDate.xml");
    final ZonedDateTime issueDateZdUtc =
        ZonedDateTime.of(2027, Month.APRIL.getValue(), 30, 3, 42, 0, 0, ZoneOffset.UTC);

    TslModifier.modifyIssueDate(tslUnsigned, issueDateZdUtc);
    TslWriter.writeUnsigned(tslUnsigned, path);
    assertThat(TslReader.getIssueDate(tslUnsigned)).isEqualTo(issueDateZdUtc);
  }

  @Test
  void setNextUpdateToNextMonthAfterIssueDate() {
    final Path path = Path.of("target/TSL-test_modifiedIssueDateAndNextUpdate.xml");
    final ZonedDateTime issueDateZdUtc = ZonedDateTime.parse("2030-04-22T10:00:00Z");

    TslModifier.modifyIssueDateAndRelatedNextUpdate(tslUnsigned, issueDateZdUtc, 30);
    TslWriter.writeUnsigned(tslUnsigned, path);
    assertThat(TslReader.getIssueDate(tslUnsigned)).isEqualTo(issueDateZdUtc);
    final ZonedDateTime nextUpdate = TslReader.getNextUpdate(tslUnsigned);
    assertThat(nextUpdate.getMonth()).isEqualTo(Month.MAY);
    assertThat(nextUpdate.toInstant()).hasToString("2030-05-22T10:00:00Z");
  }

  @Test
  void modifyTslDownloadUrls() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrls.xml");
    final String tslDnlUrlPrimary = "http://download-primary/myNewTsl.xml";
    final String tslDnlUrlBackup = "http://download-backup/myNewTsl.xml";
    TslModifier.setOtherTSLPointers(
        tslUnsigned,
        Map.of(
            TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY,
            tslDnlUrlPrimary,
            TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP,
            tslDnlUrlBackup));
    TslWriter.writeUnsigned(tslUnsigned, path);

    assertThat(TslReader.getTslDownloadUrlPrimary(tslUnsigned)).isEqualTo(tslDnlUrlPrimary);
    assertThat(TslReader.getTslDownloadUrlBackup(tslUnsigned)).isEqualTo(tslDnlUrlBackup);
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
        tslUnsigned,
        Map.of(
            TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY,
            tslDnlUrlPrimary,
            TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP + ".00",
            tslDnlUrlBackup));
    TslWriter.writeUnsigned(tslUnsigned, destFilePath);

    assertThat(TslReader.getTslDownloadUrlPrimary(tslUnsigned)).isEqualTo(tslDnlUrlPrimary);
    assertThatThrownBy(() -> TslReader.getTslDownloadUrlBackup(tslUnsigned))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessageContaining(TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP);
  }

  @Test
  void modifyTslDownloadUrlPrimary() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrlPrimary.xml");
    final String tslDnlUrlPrimary = "http://download-primary-only/myNewTsl.xml";

    TslModifier.modifyTslDownloadUrlPrimary(tslUnsigned, tslDnlUrlPrimary);
    TslWriter.writeUnsigned(tslUnsigned, path);

    assertThat(TslReader.getTslDownloadUrlPrimary(tslUnsigned)).isEqualTo(tslDnlUrlPrimary);
  }

  @Test
  void modifyTslDownloadUrlbackup() {
    final Path path = Path.of("target/TSL-test_modifiedTslDownloadUrlBackup.xml");
    final String tslDnlUrlBackup = "http://download-backup-only/myNewTsl.xml";

    TslModifier.modifyTslDownloadUrlBackup(tslUnsigned, tslDnlUrlBackup);
    TslWriter.writeUnsigned(tslUnsigned, path);

    assertThat(TslReader.getTslDownloadUrlBackup(tslUnsigned)).isEqualTo(tslDnlUrlBackup);
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
  void nonNullTestsPart1() {
    assertNonNullParameter(
        () ->
            TslModifier.modifySspForCAsOfTsp(
                null, "gematik", "http://my.new-service-supply-point:8080/ocsp"),
        "tsl");

    assertNonNullParameter(
        () ->
            TslModifier.modifySspForCAsOfTsp(
                tslUnsigned, null, "http://my.new-service-supply-point:8080/ocsp"),
        "tspName");

    assertNonNullParameter(
        () -> TslModifier.modifySspForCAsOfTsp(tslUnsigned, "gematik", null), "newSsp");

    assertNonNullParameter(() -> TslModifier.modifySequenceNr(null, 42), "tsl");

    assertNonNullParameter(() -> TslModifier.modifyNextUpdate(null, ZonedDateTime.now()), "tsl");

    assertNonNullParameter(() -> TslModifier.modifyNextUpdate(tslUnsigned, null), "zdt");

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
        () -> TslModifier.setOtherTSLPointers(tslUnsigned, null), "tslPointerValues");

    assertNonNullParameter(() -> TslModifier.modifyTslDownloadUrlPrimary(null, "foo"), "tsl");

    assertNonNullParameter(() -> TslModifier.modifyTslDownloadUrlPrimary(tslUnsigned, null), "url");

    assertNonNullParameter(() -> TslModifier.modifyTslDownloadUrlBackup(null, "foo"), "tsl");

    assertNonNullParameter(() -> TslModifier.modifyTslDownloadUrlBackup(tslUnsigned, null), "url");
    assertNonNullParameter(
        () -> TslModifier.modifySignerCert(tslUnsigned, null), "x509CertificateEncoded");
  }

  @Test
  void nonNullTestsPart2() {
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

    assertNonNullParameter(() -> TslModifier.modifyIssueDate(tslUnsigned, null), "zdt");

    assertNonNullParameter(
        () -> TslModifier.modifyIssueDateAndRelatedNextUpdate(null, ZonedDateTime.now(), 42),
        "tsl");

    assertNonNullParameter(
        () -> TslModifier.modifyIssueDateAndRelatedNextUpdate(tslUnsigned, null, 42), "issueDate");

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
        () -> TslModifier.deleteSspsForCAsOfEndEntity(tslUnsigned, null, PRODUCT_TYPE),
        "x509EeCert");

    assertNonNullParameter(
        () -> TslModifier.deleteSspsForCAsOfEndEntity(tslUnsigned, eeCert, null), "productType");
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
  void testModifySignerCert() {

    tslUnsigned = TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT);
    final X509Certificate oldSignerCert = TslUtils.getFirstTslSignerCertificate(tslUnsigned);
    final X509Certificate eeCert = INVALID_EXTENSION_NOT_CRIT_CERT;
    assertThat(oldSignerCert).isNotEqualTo(eeCert);

    final byte[] tslBytes = TslConverter.tslUnsignedToBytes(tslUnsigned);
    final byte[] tslBytesNew = TslModifier.modifiedSignerCert(tslBytes, eeCert);
    final String tslStrNew = new String(tslBytesNew, StandardCharsets.UTF_8);

    final TrustStatusListType tslNewUnsigned = TslConverter.bytesToTslUnsigned(tslBytesNew);
    final X509Certificate eeCertNew = TslUtils.getFirstTslSignerCertificate(tslNewUnsigned);

    assertThat(eeCertNew).isEqualTo(eeCert);
    assertSignerCertInTsl(tslStrNew, eeCert);
  }

  @Test
  void testGetXmlGregorianCalendarException() {
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
  void testGetXmlGregorianCalendarNonNull() {
    assertNonNullParameter(() -> TslModifier.getXmlGregorianCalendar(null), "zdt");
  }

  @Test
  void testModifyWithSameSignerCert() {

    tslUnsigned = TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT);
    final X509Certificate signerCertFromTsl = TslUtils.getFirstTslSignerCertificate(tslUnsigned);

    final byte[] tslBytes = TslConverter.tslUnsignedToBytes(tslUnsigned);
    final byte[] tslBytesNew = TslModifier.modifiedSignerCert(tslBytes, signerCertFromTsl);
    final String tslStrNew = new String(tslBytesNew, StandardCharsets.UTF_8);

    final TrustStatusListType tslNewUnsigned = TslConverter.bytesToTslUnsigned(tslBytesNew);

    final X509Certificate signerCertNew = TslUtils.getFirstTslSignerCertificate(tslNewUnsigned);

    assertThat(signerCertNew).isEqualTo(signerCertFromTsl);

    assertSignerCertInTsl(tslStrNew, signerCertFromTsl);
  }

  @Test
  void testModifiedPrettyPrint() {
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
  void testModifiedPrettyPrintAndSign() {

    final TslSignerBuilder tslSignerBuilder = TslSigner.builder();
    final P12Container signerEcc = readP12(SIGNER_PATH_ECC);

    final Document tslDoc = TslConverter.tslToDocUnsigned(tslUnsigned);
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
  void testModifiedTslIdStr() {
    final String newTslId = "newId_" + GemLibPkiUtils.now();
    final byte[] modifiedTslBytes =
        TslModifier.modifiedTslId(TslConverter.tslUnsignedToBytes(tslUnsigned), newTslId);

    final TrustStatusListType tslUnsigned = TslConverter.bytesToTslUnsigned(modifiedTslBytes);

    assertThat(tslUnsigned.getId()).isEqualTo(newTslId);
  }

  @Test
  void testModifiedTslIdTslSeqNrIssueDate() {
    final ZonedDateTime issueDate = GemLibPkiUtils.now().minusYears(1);
    final int tslSeqNr = 900001;
    final String expectedTslId = TslModifier.generateTslId(tslSeqNr, issueDate);

    final byte[] modifiedTslBytes =
        TslModifier.modifiedTslId(
            TslConverter.tslUnsignedToBytes(tslUnsigned), tslSeqNr, issueDate);

    final TrustStatusListType tslUnsigned = TslConverter.bytesToTslUnsigned(modifiedTslBytes);

    assertThat(tslUnsigned.getId()).isEqualTo(expectedTslId);

    final byte[] tslBytesUnsigned = TslConverter.tslUnsignedToBytes(tslUnsigned);
    assertNonNullParameter(
        () -> TslModifier.modifiedTslId(tslBytesUnsigned, tslSeqNr, null), "issueDate");
  }

  @Test
  void testModifiedGematikDefaultTspTradeName() {

    final byte[] tslBytes = TslConverter.tslUnsignedToBytes(tslUnsigned);
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
  void testModifiedStatusStartingTimeOfAnnouncedTrustAnchor()
      throws DatatypeConfigurationException {

    final TrustStatusListType oldTsl = TestUtils.getTslUnsigned("tsls/ecc/valid/TSL_TAchange.xml");

    final String tspNameToSelect = "gematik GmbH - PKI TEST TSP";
    final String serviceIdentifierToSelect = TslConstants.STI_SRV_CERT_CHANGE;
    final String serviceStatusToSelect = null;

    final XMLGregorianCalendar oldStartingStatusTimeGreg =
        DatatypeFactory.newInstance().newXMLGregorianCalendar("2023-04-20T14:47:40Z");

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
                      .get(0)
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
  void testDeleteSignature() {

    final TrustStatusListType tsl = TestUtils.getTslUnsigned("tsls/ecc/valid/TSL_TAchange.xml");
    assertThat(tsl.getSignature()).isNotNull();

    TslModifier.deleteSignature(tsl);
    assertThat(tsl.getSignature()).isNull();
  }

  @Test
  void testModifyStatusStartingTime() {

    final String gematikTspName = "gematik GmbH - PKI TEST TSP";
    final ZonedDateTime now = GemLibPkiUtils.now();
    assertDoesNotThrow(
        () ->
            TslModifier.modifyStatusStartingTime(
                tslUnsigned,
                gematikTspName,
                TslConstants.STI_PKC,
                TslConstants.SVCSTATUS_INACCORD,
                now));
  }
}
