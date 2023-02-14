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

import static de.gematik.pki.gemlibpki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_TSL_CA8;
import static de.gematik.pki.gemlibpki.utils.TestUtils.overwriteSspUrls;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.pki.gemlibpki.common.OcspResponderMock;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
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
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import javax.xml.bind.JAXBElement;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;

class TucPki001VerifierTest {

  private static List<TspService> tspServicesInTruststore;
  private static byte[] tslToCheck;
  private static TrustStatusListType tslToCheckTsl;

  @BeforeAll
  static void start() {
    tslToCheckTsl = TestUtils.getDefaultTsl();
    final Document tslToCheckDoc = TestUtils.getDefaultTslAsDoc();
    tslToCheck = TslConverter.docToBytes(tslToCheckDoc);
    tspServicesInTruststore = new TslInformationProvider(tslToCheckTsl).getTspServices();
    overwriteSspUrls(tspServicesInTruststore, "invalidSsp");
  }

  @Test
  void verifyPerformTucPki001ChecksValid() {
    final OcspResponderMock ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    final X509Certificate tslSigner =
        TestUtils.readP12(TslSignerTest.SIGNER_PATH_ECC).getCertificate();
    ocspResponderMock.configureForOcspRequest(tslSigner, VALID_ISSUER_CERT_TSL_CA8);
    overwriteSspUrls(tspServicesInTruststore, ocspResponderMock.getSspUrl());

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentSeqNr(BigInteger.ZERO)
            .build();
    assertDoesNotThrow(tucPki001Verifier::performTucPki001Checks);
  }

  @Test
  void verifyGetTslSignerCertificateInvalidFindFirst() {

    final TrustStatusListType tslToCheck = TestUtils.getDefaultTsl();
    tslToCheck.getSignature().getKeyInfo().getContent().clear();
    final byte[] tslBytes = TslConverter.tslToBytes(tslToCheck);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::getTslSignerCertificate)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyGetTslSignerCertificateInvalidManyChanges() {

    final TrustStatusListType tslToCheck = TestUtils.getDefaultTsl();

    final JAXBElement<byte[]> signatureCertificateJaxbElem =
        TslUtils.getFirstSignatureCertificateJaxbElement(tslToCheck);

    signatureCertificateJaxbElem.setValue(
        "invalidbytesX509Certificate".getBytes(StandardCharsets.UTF_8));

    final byte[] tslBytes = TslConverter.tslToBytes(tslToCheck);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::getTslSignerCertificate)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyGetTslSignerCertificateInvalidFewChanges() {

    final TrustStatusListType tslToCheck = TestUtils.getDefaultTsl();

    final JAXBElement<byte[]> signatureCertificateJaxbElem =
        TslUtils.getFirstSignatureCertificateJaxbElement(tslToCheck);

    // TODO warum nicht change4byte()?
    final byte[] bytes = signatureCertificateJaxbElem.getValue();

    // change content
    for (int i = 0; i < 9; ++i) {
      bytes[i] = '*';
    }
    final byte[] tslBytes = TslConverter.tslToBytes(tslToCheck);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentSeqNr(BigInteger.ZERO)
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
            .currentSeqNr(BigInteger.ZERO)
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
            .currentSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
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
            .generate(ocspReq, tslSigner, unknownStatus);
    ocspResponderMock.configureWireMockReceiveHttpPost(ocspRespLocal, HttpURLConnection.HTTP_OK);
    overwriteSspUrls(tspServicesInTruststore, ocspResponderMock.getSspUrl());

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentSeqNr(BigInteger.ZERO)
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TW_1044_CERT_UNKNOWN.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyNullChecks() {
    final TucPki001VerifierBuilder builder = TucPki001Verifier.builder();

    assertThatThrownBy(() -> builder.productType(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("productType is marked non-null but is null");

    assertThatThrownBy(() -> builder.tslToCheck(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tslToCheck is marked non-null but is null");

    assertThatThrownBy(() -> builder.currentTrustedServices(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("currentTrustedServices is marked non-null but is null");
  }

  private void verifyPerformTucPki001ChecksTslIdAndSeqNr_init() {
    final OcspResponderMock ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    final X509Certificate tslSigner =
        TestUtils.readP12(TslSignerTest.SIGNER_PATH_ECC).getCertificate();
    ocspResponderMock.configureForOcspRequest(tslSigner, VALID_ISSUER_CERT_TSL_CA8);
    overwriteSspUrls(tspServicesInTruststore, ocspResponderMock.getSspUrl());
  }

  @Test
  void verifyPerformTucPki001ChecksTslIdAndSeqNr_SameIdAndSameSeqNr_NotForUpdate() {
    verifyPerformTucPki001ChecksTslIdAndSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId(tslToCheckTsl.getId())
            .currentSeqNr(tslToCheckTsl.getSchemeInformation().getTSLSequenceNumber())
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1007_TSL_ID_INCORRECT.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyPerformTucPki001ChecksTslIdAndSeqNr_DifferentIdsAndIncrementedSeqNr_ForUpdate() {

    verifyPerformTucPki001ChecksTslIdAndSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentSeqNr(
                tslToCheckTsl
                    .getSchemeInformation()
                    .getTSLSequenceNumber()
                    .subtract(BigInteger.ONE))
            .build();

    assertDoesNotThrow(tucPki001Verifier::performTucPki001Checks);
  }

  @Test
  void verifyPerformTucPki001ChecksTslIdAndSeqNr_Check1NewSeqNrIsSmallerThanCurrentSeqNr() {

    verifyPerformTucPki001ChecksTslIdAndSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentSeqNr(
                tslToCheckTsl.getSchemeInformation().getTSLSequenceNumber().add(BigInteger.ONE))
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1007_TSL_ID_INCORRECT.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyPerformTucPki001ChecksTslIdAndSeqNr_Check3NewSeqNrGreaterThanCurrentSeqNrButSameIds() {

    verifyPerformTucPki001ChecksTslIdAndSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId(tslToCheckTsl.getId())
            .currentSeqNr(
                tslToCheckTsl
                    .getSchemeInformation()
                    .getTSLSequenceNumber()
                    .subtract(BigInteger.ONE))
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1007_TSL_ID_INCORRECT.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyPerformTucPki001ChecksTslIdAndSeqNr_Check2SameSeqNrButIdsDiffer() {

    verifyPerformTucPki001ChecksTslIdAndSeqNr_init();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummy_" + tslToCheckTsl.getId())
            .currentSeqNr(tslToCheckTsl.getSchemeInformation().getTSLSequenceNumber())
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1007_TSL_ID_INCORRECT.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyTslTrustAnchorUpdate() {
    final X509Certificate taCert = TestUtils.readCert("GEM.TSL-CA9/GEM.TSL-CA9_TEST-ONLY.cer");

    final ZonedDateTime statusStartingTime = GemLibPkiUtils.now().minus(2, ChronoUnit.SECONDS);
    final TrustAnchorUpdate trustAnchorUpdate = new TrustAnchorUpdate(taCert, statusStartingTime);

    assertTrue(trustAnchorUpdate.isToActivateNow());
    assertTrue(trustAnchorUpdate.isToActivate(statusStartingTime.plus(1, ChronoUnit.SECONDS)));
    assertFalse(trustAnchorUpdate.isToActivate(statusStartingTime.minus(1, ChronoUnit.SECONDS)));
  }

  @Test
  void verifyNoTaUpdatePresent() {

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentSeqNr(BigInteger.ZERO)
            .build();
    assertThat(tucPki001Verifier.getVerifiedAnnouncedTrustAnchorUpdate()).isEmpty();
  }

  @Test
  void verifyGetFutureTrustAnchor() {
    final byte[] tslBytes =
        TslConverter.tslToBytes(TestUtils.getTsl("tsls/ecc/valid/TSL_TAchange.xml"));
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentSeqNr(BigInteger.ZERO)
            .build();

    final TrustAnchorUpdate trustAnchorUpdate =
        tucPki001Verifier.getVerifiedAnnouncedTrustAnchorUpdate().orElseThrow();

    final ZonedDateTime zdt = ZonedDateTime.of(2022, 9, 12, 16, 44, 34, 0, ZoneOffset.UTC);
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
    final byte[] tslBytes = TslConverter.tslToBytes(TestUtils.getTsl("tsls/ecc/defect/" + tslPath));
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentSeqNr(BigInteger.ZERO)
            .build();
    assertThat(tucPki001Verifier.getVerifiedAnnouncedTrustAnchorUpdate())
        .isEmpty(); // TODO check warn message
  }

  @Test
  void verifyExceptionInTaAnnouncement() {
    final TrustStatusListType tsl = TestUtils.getTsl("tsls/ecc/valid/TSL_TAchange.xml");

    for (final TSPType tspType : tsl.getTrustServiceProviderList().getTrustServiceProvider()) {
      for (final TSPServiceType tspServiceType : tspType.getTSPServices().getTSPService()) {
        tspServiceType.setServiceInformation(null);
      }
    }
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(TslConverter.tslToBytes(tsl))
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyId")
            .currentSeqNr(BigInteger.ZERO)
            .build();

    assertThat(tucPki001Verifier.getVerifiedAnnouncedTrustAnchorUpdate()).isEmpty();
  }
}
