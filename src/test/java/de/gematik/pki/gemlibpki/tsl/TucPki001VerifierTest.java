/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_TSL_CA8;
import static de.gematik.pki.gemlibpki.tsl.TslConverter.ERROR_READING_TSL;
import static de.gematik.pki.gemlibpki.tsl.TslUtils.getFirstTslSignerCertificate;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getFileFromResourceAsBytes;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.utils.TestUtils.overwriteSspUrls;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.pki.gemlibpki.common.OcspResponderMock;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.ocsp.OcspTestConstants;
import de.gematik.pki.gemlibpki.tsl.TucPki001Verifier.TrustAnchorUpdate;
import de.gematik.pki.gemlibpki.tsl.TucPki001Verifier.TucPki001VerifierBuilder;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.JAXBElement;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Validator;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

class TucPki001VerifierTest {

  private static List<TspService> tspServicesInTruststore;
  private static byte[] tslToCheck;
  private static TrustStatusListType tslToCheckTslUnsigned;

  @BeforeAll
  static void start() {
    tslToCheckTslUnsigned = TestUtils.getDefaultTslUnsigned();
    final Document tslToCheckDoc = TestUtils.getDefaultTslAsDoc();
    tslToCheck = TslConverter.docToBytes(tslToCheckDoc);
    tspServicesInTruststore = new TslInformationProvider(tslToCheckTslUnsigned).getTspServices();
    overwriteSspUrls(tspServicesInTruststore, "invalidSsp");
  }

  @Test
  void verifyPerformTucPki001ChecksValid() {
    final OcspResponderMock ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    final X509Certificate tslSigner = getFirstTslSignerCertificate(tslToCheckTslUnsigned);

    ocspResponderMock.configureForOcspRequest(tslSigner, VALID_ISSUER_CERT_TSL_CA8);
    overwriteSspUrls(tspServicesInTruststore, ocspResponderMock.getSspUrl());

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();
    assertDoesNotThrow(tucPki001Verifier::performTucPki001Checks);
  }

  @Test
  void verifyInvalidTslSig() {
    final byte[] tslBytesUnsigned = TslConverter.tslUnsignedToBytes(tslToCheckTslUnsigned);

    final X509Certificate tslSigner = getFirstTslSignerCertificate(tslToCheckTslUnsigned);

    final OcspResponderMock ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    ocspResponderMock.configureForOcspRequest(tslSigner, VALID_ISSUER_CERT_TSL_CA8);
    overwriteSspUrls(tspServicesInTruststore, ocspResponderMock.getSspUrl());

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytesUnsigned)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1013_XML_SIGNATURE_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyGetTslSignerCertificateInvalidFindFirst() {

    final TrustStatusListType tslToCheckUnsigned = TestUtils.getDefaultTslUnsigned();
    tslToCheckUnsigned.getSignature().getKeyInfo().getContent().clear();
    final byte[] tslBytesUnsigned = TslConverter.tslUnsignedToBytes(tslToCheckUnsigned);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytesUnsigned)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::getTslSignerCertificate)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyGetTslSignerCertificateInvalidManyChanges() {

    final TrustStatusListType tslToCheckUnsigned = TestUtils.getDefaultTslUnsigned();

    final JAXBElement<byte[]> signatureCertificateJaxbElem =
        TslUtils.getFirstSignatureCertificateJaxbElement(tslToCheckUnsigned);

    signatureCertificateJaxbElem.setValue(
        "invalidbytesX509Certificate".getBytes(StandardCharsets.UTF_8));

    final byte[] tslBytesUnsigned = TslConverter.tslUnsignedToBytes(tslToCheckUnsigned);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytesUnsigned)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::getTslSignerCertificate)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyGetTslSignerCertificateInvalidFewChanges() {

    final TrustStatusListType tslToCheckUnsigned = TestUtils.getDefaultTslUnsigned();

    final JAXBElement<byte[]> signatureCertificateJaxbElem =
        TslUtils.getFirstSignatureCertificateJaxbElement(tslToCheckUnsigned);

    final byte[] bytes = signatureCertificateJaxbElem.getValue();
    GemLibPkiUtils.change4Bytes(bytes, 4);

    final byte[] tslBytesUnsigned = TslConverter.tslUnsignedToBytes(tslToCheckUnsigned);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytesUnsigned)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::getTslSignerCertificate)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyPerformTucPki001ChecksOcspDisabled() {
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .withOcspCheck(false)
            .build();
    assertDoesNotThrow(tucPki001Verifier::performTucPki001Checks);
  }

  @Test
  void verifyPerformTucPki001ChecksWithoutOcspInvalid() {

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyTslValidityValidNextUpdate() {
    final ZonedDateTime issueDate = TslReader.getIssueDate(tslToCheckTslUnsigned);
    assertDoesNotThrow(
        () ->
            TucPki001Verifier.verifyTslValidity(issueDate, 0, tslToCheckTslUnsigned, PRODUCT_TYPE));
  }

  @Test
  void verifyTslValidityValidNextUpdateInGracePeriod() {
    final ZonedDateTime nextUpdate = TslReader.getNextUpdate(tslToCheckTslUnsigned);
    assertDoesNotThrow(
        () ->
            TucPki001Verifier.verifyTslValidity(
                nextUpdate.plusDays(2), 5, tslToCheckTslUnsigned, PRODUCT_TYPE));
  }

  @Test
  void verifyTslValidityWarn2() {
    final ZonedDateTime nextUpdate = TslReader.getNextUpdate(tslToCheckTslUnsigned);

    assertThatThrownBy(
            () ->
                TucPki001Verifier.verifyTslValidity(
                    nextUpdate.plusSeconds(1), 0, tslToCheckTslUnsigned, PRODUCT_TYPE))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SW_1009_VALIDITY_WARNING_2.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyPerformTucPki001ChecksOcspStatusUnknown() {

    final OcspResponderMock ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    final X509Certificate tslSigner =
        TestUtils.readP12(TslSignerTest.SIGNER_PATH_ECC).getCertificate();
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(tslSigner, VALID_ISSUER_CERT_TSL_CA8);
    final CertificateStatus unknownStatus = new UnknownStatus();
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, tslSigner, VALID_ISSUER_CERT_TSL_CA8, unknownStatus);
    ocspResponderMock.configureWireMockReceiveHttpPost(ocspRespLocal, HttpURLConnection.HTTP_OK);
    overwriteSspUrls(tspServicesInTruststore, ocspResponderMock.getSspUrl());

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TW_1044_CERT_UNKNOWN.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyNullChecks() {
    final TucPki001VerifierBuilder builder = TucPki001Verifier.builder();

    assertNonNullParameter(() -> builder.productType(null), "productType");

    assertNonNullParameter(() -> builder.tslToCheck(null), "tslToCheck");

    assertNonNullParameter(() -> builder.currentTrustedServices(null), "currentTrustedServices");
  }

  private void verifyPerformTucPki001ChecksTslIdAndTslSeqNr_init() {
    final OcspResponderMock ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    final X509Certificate tslSigner = getFirstTslSignerCertificate(tslToCheckTslUnsigned);
    ocspResponderMock.configureForOcspRequest(tslSigner, VALID_ISSUER_CERT_TSL_CA8);
    overwriteSspUrls(tspServicesInTruststore, ocspResponderMock.getSspUrl());
  }

  @Test
  void verifyPerformTucPki001ChecksTslIdAndTslSeqNr_SameIdAndSameTslSeqNr_NotForUpdate() {
    verifyPerformTucPki001ChecksTslIdAndTslSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId(tslToCheckTslUnsigned.getId())
            .currentTslSeqNr(tslToCheckTslUnsigned.getSchemeInformation().getTSLSequenceNumber())
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1007_TSL_ID_INCORRECT.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyPerformTucPki001ChecksTslIdAndTslSeqNr_DifferentIdsAndIncrementedTslSeqNr_ForUpdate() {

    verifyPerformTucPki001ChecksTslIdAndTslSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(
                tslToCheckTslUnsigned
                    .getSchemeInformation()
                    .getTSLSequenceNumber()
                    .subtract(BigInteger.ONE))
            .build();

    assertDoesNotThrow(tucPki001Verifier::performTucPki001Checks);
  }

  @Test
  void
      verifyPerformTucPki001ChecksTslIdAndTslSeqNr_Check1NewTslSeqNrIsSmallerThanCurrentTslSeqNr() {

    verifyPerformTucPki001ChecksTslIdAndTslSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(
                tslToCheckTslUnsigned
                    .getSchemeInformation()
                    .getTSLSequenceNumber()
                    .add(BigInteger.ONE))
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1007_TSL_ID_INCORRECT.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      verifyPerformTucPki001ChecksTslIdAndTslSeqNr_Check3NewTslSeqNrGreaterThanCurrentTslSeqNrButSameIds() {

    verifyPerformTucPki001ChecksTslIdAndTslSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId(tslToCheckTslUnsigned.getId())
            .currentTslSeqNr(
                tslToCheckTslUnsigned
                    .getSchemeInformation()
                    .getTSLSequenceNumber()
                    .subtract(BigInteger.ONE))
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1007_TSL_ID_INCORRECT.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyPerformTucPki001ChecksTslIdAndTslSeqNr_Check2SameTslSeqNrButIdsDiffer() {

    verifyPerformTucPki001ChecksTslIdAndTslSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummy_" + tslToCheckTslUnsigned.getId())
            .currentTslSeqNr(tslToCheckTslUnsigned.getSchemeInformation().getTSLSequenceNumber())
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1007_TSL_ID_INCORRECT.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyTslTrustAnchorUpdate() {
    final X509Certificate taCert = TestUtils.readCert("GEM.TSL-CA9/GEM.TSL-CA9_TEST-ONLY.cer");

    final ZonedDateTime statusStartingTime = GemLibPkiUtils.now().minusSeconds(2);
    final TrustAnchorUpdate trustAnchorUpdate = new TrustAnchorUpdate(taCert, statusStartingTime);

    assertTrue(trustAnchorUpdate.isToActivateNow());
    assertTrue(trustAnchorUpdate.isToActivate(statusStartingTime.plusSeconds(1)));
    assertFalse(trustAnchorUpdate.isToActivate(statusStartingTime.minusSeconds(1)));
  }

  @Test
  void verifyNoTaUpdatePresent() {

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();
    assertThat(tucPki001Verifier.getVerifiedAnnouncedTrustAnchorUpdate()).isEmpty();
  }

  @Test
  void verifyGetFutureTrustAnchor() {
    final byte[] tslBytes =
        TslConverter.tslUnsignedToBytes(
            TestUtils.getTslUnsigned("tsls/ecc/valid/TSL_TAchange.xml"));
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    final TrustAnchorUpdate trustAnchorUpdate =
        tucPki001Verifier.getVerifiedAnnouncedTrustAnchorUpdate().orElseThrow();

    final ZonedDateTime zdt = ZonedDateTime.of(2023, 4, 20, 14, 47, 40, 0, ZoneOffset.UTC);
    final X509Certificate taCert = TestUtils.readCert("GEM.TSL-CA9/GEM.TSL-CA9_TEST-ONLY.cer");
    assertThat(trustAnchorUpdate.getStatusStartingTime()).isEqualToIgnoringNanos(zdt);
    assertThat(trustAnchorUpdate.getFutureTrustAnchor()).isEqualTo(taCert);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "TSL_defect_TAchange_twoEntries.xml",
        "TSL_defect_TAchange_broken.xml",
        "TSL_defect_TAchange_notYetValid.xml"
      })
  void verifyMultipleTaUpdatesPresent(final String tslPath) {
    final byte[] tslBytes =
        TslConverter.tslUnsignedToBytes(TestUtils.getTslUnsigned("tsls/ecc/defect/" + tslPath));
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThat(tucPki001Verifier.getVerifiedAnnouncedTrustAnchorUpdate())
        .isEmpty(); // NOTE: warn messages are not automatically checked
  }

  @Test
  void verifyExceptionInTaAnnouncement() {
    final TrustStatusListType tslUnsigned =
        TestUtils.getTslUnsigned("tsls/ecc/valid/TSL_TAchange.xml");

    for (final TSPType tspType :
        tslUnsigned.getTrustServiceProviderList().getTrustServiceProvider()) {
      for (final TSPServiceType tspServiceType : tspType.getTSPServices().getTSPService()) {
        tspServiceType.setServiceInformation(null);
      }
    }
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(TslConverter.tslUnsignedToBytes(tslUnsigned))
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThat(tucPki001Verifier.getVerifiedAnnouncedTrustAnchorUpdate()).isEmpty();
  }

  @Test
  void verifyValidateSchemesValid() {

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertDoesNotThrow(tucPki001Verifier::validateAgainstXsdSchemas);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "tsls/ecc/invalid/TSL_invalid_xmlNonEtsiTag_altCA.xml",
        "tsls/ecc/invalid/TSL_invalid_xmlNamespace_altCA.xml"
      })
  void verifyValidateSchemesInvalid(final String tslFilename) {
    final byte[] tslBytes = getFileFromResourceAsBytes(tslFilename, TucPki001VerifierTest.class);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::validateAgainstXsdSchemas)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1012_TSL_SCHEMA_NOT_VALID.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyInvalidSchema() {

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(() -> tucPki001Verifier.validateAgainstXsd("schemas/invalid.xsd"))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error during parsing of schema file.");
  }

  @Test
  void verifyInvalidSchema_IOException() throws IOException, SAXException {

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    final Validator validatorSpy = Mockito.spy(Validator.class);
    Mockito.doThrow(IOException.class).when(validatorSpy).validate(Mockito.any());

    final TucPki001Verifier tucPki001VerifierSpy = Mockito.spy(tucPki001Verifier);
    Mockito.doReturn(validatorSpy).when(tucPki001VerifierSpy).getValidator(Mockito.any());

    assertThatThrownBy(
            () -> tucPki001VerifierSpy.validateAgainstXsd("schemas/ts_102231v030102_xsd.xsd"))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Error reading schema file.")
        .cause()
        .isInstanceOf(IOException.class);
  }

  @Test
  void verifyWellFormedXml() {

    final byte[] tslToCheckBroken = Arrays.copyOfRange(tslToCheck, 0, tslToCheck.length - 1);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheckBroken)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::validateWellFormedXml)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1011_TSL_NOT_WELLFORMED.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void testValidateWellFormedXmlException() {
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();

    try (final MockedStatic<TslUtils> tslUtils = Mockito.mockStatic(TslUtils.class)) {
      tslUtils.when(TslUtils::createDocBuilder).thenThrow(new ParserConfigurationException());
      assertThatThrownBy(tucPki001Verifier::validateWellFormedXml)
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage(ERROR_READING_TSL);
    }
  }
}
