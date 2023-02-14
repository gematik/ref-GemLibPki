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

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.GEMATIK_TEST_TSP_NAME;
import static de.gematik.pki.gemlibpki.tsl.TslSignerTest.SIGNER_PATH_ECC;
import static de.gematik.pki.gemlibpki.utils.TestUtils.readP12;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.tsl.TslConverter.DocToBytesOption;
import de.gematik.pki.gemlibpki.tsl.TslSigner.TslSignerBuilder;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
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
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslModifierTest {

  private TrustStatusListType tsl;

  @BeforeEach
  void setup() {
    tsl = TestUtils.getDefaultTsl();
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

  private void assertSignerCertInTsl(final String tslStr, final X509Certificate signerCert)
      throws CertificateEncodingException {

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
  void testModifySignerCert() throws CertificateEncodingException {

    tsl = TestUtils.getTsl(FILE_NAME_TSL_ECC_DEFAULT);
    final String tslStr =
        new String(
            GemLibPkiUtils.readContent(
                ResourceReader.getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT)),
            StandardCharsets.UTF_8);

    final X509Certificate eeCert =
        TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther_invalid-extension-not-crit.pem");

    final X509Certificate oldSignerCert = TslUtils.getFirstTslSignerCertificate(tsl);

    assertThat(oldSignerCert).isNotEqualTo(eeCert);

    assertSignerCertInTsl(tslStr, oldSignerCert);

    final byte[] tslBytes = TslConverter.tslToBytes(tsl);
    final byte[] tslBytesNew = TslModifier.modifiedSignerCert(tslBytes, eeCert);
    final String tslStrNew = new String(tslBytesNew, StandardCharsets.UTF_8);

    final TrustStatusListType tslNew = TslConverter.bytesToTsl(tslBytesNew);

    final X509Certificate eeCertNew = TslUtils.getFirstTslSignerCertificate(tslNew);

    assertThat(eeCertNew).isEqualTo(eeCert);
    assertSignerCertInTsl(tslStrNew, eeCert);
  }

  @Test
  void testModifyWithSameSignerCert() throws CertificateEncodingException {

    tsl = TestUtils.getTsl(FILE_NAME_TSL_ECC_DEFAULT);
    final String tslStr =
        new String(
            GemLibPkiUtils.readContent(
                ResourceReader.getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT)),
            StandardCharsets.UTF_8);

    final X509Certificate signerCert = TslUtils.getFirstTslSignerCertificate(tsl);

    assertSignerCertInTsl(tslStr, signerCert);

    final byte[] tslBytes = TslConverter.tslToBytes(tsl);
    final byte[] tslBytesNew = TslModifier.modifiedSignerCert(tslBytes, signerCert);
    final String tslStrNew = new String(tslBytesNew, StandardCharsets.UTF_8);

    final TrustStatusListType tslNew = TslConverter.bytesToTsl(tslBytesNew);

    final X509Certificate signerCertNew = TslUtils.getFirstTslSignerCertificate(tslNew);

    assertThat(signerCertNew).isEqualTo(signerCert);

    assertSignerCertInTsl(tslStrNew, signerCert);
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

    final Document tslDoc = TslConverter.tslToDoc(tsl);
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
                    new String(signedTslBytes, StandardCharsets.UTF_8), indentationIndicator)
                < 100)
        .isTrue();

    final Document tslDoc2 = TslConverter.bytesToDoc(tslBytes);

    final byte[] tslBytesPrettyPrinted =
        TslConverter.docToBytes(tslDoc2, DocToBytesOption.PRETTY_PRINT);
    final Document tslDocPrettyPrinted = TslConverter.bytesToDoc(tslBytesPrettyPrinted);
    tslSignerBuilder.tslToSign(tslDocPrettyPrinted).tslSignerP12(signerEcc).build().sign();

    final byte[] signedAndPrettyPrintedTslBytes = TslConverter.docToBytes(tslDocPrettyPrinted);

    int countIndentationIndicator =
        StringUtils.countMatches(
            new String(tslBytesPrettyPrinted, StandardCharsets.UTF_8), indentationIndicator);
    assertThat(countIndentationIndicator > 5000).isTrue();

    countIndentationIndicator =
        StringUtils.countMatches(
            new String(signedAndPrettyPrintedTslBytes, StandardCharsets.UTF_8),
            indentationIndicator);
    assertThat(countIndentationIndicator > 5000).isTrue();
  }

  @Test
  void testModifiedTslIdStr() {
    final String newTslId = "newId_" + GemLibPkiUtils.now();
    final byte[] modifiedTslBytes =
        TslModifier.modifiedTslId(TslConverter.tslToBytes(tsl), newTslId);

    final TrustStatusListType tsl = TslConverter.bytesToTsl(modifiedTslBytes);

    assertThat(tsl.getId()).isEqualTo(newTslId);
  }

  @Test
  void testModifiedTslIdSeqNrIssueDate() {
    final ZonedDateTime issueDate = GemLibPkiUtils.now().minusYears(1);
    final int seqNr = 900001;
    final String expectedTslId = TslModifier.generateTslId(seqNr, issueDate);

    final byte[] modifiedTslBytes =
        TslModifier.modifiedTslId(TslConverter.tslToBytes(tsl), seqNr, issueDate);

    final TrustStatusListType tsl = TslConverter.bytesToTsl(modifiedTslBytes);

    assertThat(tsl.getId()).isEqualTo(expectedTslId);

    final byte[] tslBytes = TslConverter.tslToBytes(tsl);
    assertThatThrownBy(() -> TslModifier.modifiedTslId(tslBytes, seqNr, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("issueDate is marked non-null but is null");
  }

  @Test
  void testModifiedGematikDefaultTspTradeName() {

    final byte[] tslBytes = TslConverter.tslToBytes(tsl);
    final String tslStr = new String(tslBytes, StandardCharsets.UTF_8);

    final String gematikTspName =
        "gematik Gesellschaft fuer Telematikanwendungen der Gesundheitskarte mbH TSL Signer CA4";
    final String gematikOldTspTradeName = "gematik Test-TSL: TSL_default";
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

    final TrustStatusListType oldTsl = TestUtils.getTsl("tsls/ecc/valid/TSL_TAchange.xml");

    final String tspNameToSelect = "gematik GmbH - PKI TEST TSP";
    final String serviceIdentifierToSelect = TslConstants.STI_SRV_CERT_CHANGE;
    final String serviceStatusToSelect = null;

    final XMLGregorianCalendar oldStartingStatusTimeGreg =
        DatatypeFactory.newInstance().newXMLGregorianCalendar("2022-09-12T16:44:34Z");

    final ZonedDateTime newStartingStatusTime = GemLibPkiUtils.now();
    final XMLGregorianCalendar newStartingStatusTimeGreg =
        TslModifier.getXmlGregorianCalendar(newStartingStatusTime);

    final byte[] tslBytes = TslConverter.tslToBytes(oldTsl);

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
        TslConverter.bytesToTsl(modifiedTslBytes), newStartingStatusTimeGreg);
  }
}
