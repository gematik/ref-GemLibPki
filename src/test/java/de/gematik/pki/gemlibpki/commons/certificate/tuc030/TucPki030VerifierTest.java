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
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.OCSP_HOST;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_AND_WITHOUT_HISTORY;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_BUT_GRANTED_HISTORY;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_HISTORYENTRY_DOES_NOT_MATCH_EE_CERTIFICATE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_ISSUER_CERT_QES_ALT_CA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_ISSUER_CERT_QES_DEFAULT_CA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES_ALT_CA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES_ALT_CA_CA_ISSUER;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES_PSYCHO_TWO_ADMISSIONS;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_EXPIRED;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_MISSING_ADMISSION;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_MISSING_KEY_USAGE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_MISSING_OCSP_URL;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_MISSING_QC_STATEMENT;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_MISSING_ROLE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_NOT_YET_VALID;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_SIGNATURE_ERROR;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_WRONG_ISSUER;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_WRONG_KEY_USAGE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.X509_EE_CERT_QES_WRONG_QC_STATEMENT;
import static de.gematik.pki.gemlibpki.commons.tsl.TslConstants.SVCSTATUS_WITHDRAWN;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.generateOcspResponse;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.generateOcspResponseWithTimeStamps;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.TestConstantsNonQes;
import de.gematik.pki.gemlibpki.commons.certificate.Admission;
import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponderMock;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTestConstants;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiverFactory;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import de.gematik.pki.gemlibpki.ti20.certificate.AuthorityInformationAccessExtension;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import jakarta.xml.bind.JAXBElement;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TucPki030VerifierTest {

  private TucPki030Verifier tucPki030Verifier;
  private OCSPResp ocspResponseValid;
  private OCSPResp ocspResponseAltCa;
  private static final int SECONDS_50_AS_MILLISECS = 50000;
  private OcspResponderMock ocspResponderMock;

  private static OcspTransceiver getOcspTransceiver(final String ssp) {
    return OcspTransceiver.builder()
        .productType(PRODUCT_TYPE)
        .x509EeCert(VALID_X509_EE_CERT_QES)
        .x509IssuerCert(VALID_ISSUER_CERT_QES_DEFAULT_CA)
        .ssp(ssp)
        .tolerateOcspFailure(false)
        .build();
  }

  private void configureOcspResponderMockForOcspRequest(final Extension responseNonce) {
    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, responseNonce);
    final OCSPResp ocspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA);
    ocspResponderMock.configureWireMockReceiveHttpPost(ocspResponse, HttpURLConnection.HTTP_OK);
  }

  /**
   * Overwrites the OCSP URL in the TSL with the given new OCSP URL. Used to replace the OCSP
   * override for the QES test certificate in the test TSL with the URL of the local mock responder.
   */
  private static void overwriteOcspUrlOverride(
      final List<TspService> tspServiceListTsl, final String newOcspUrl) throws IOException {
    final String aiaOcspUrl =
        new AuthorityInformationAccessExtension(VALID_X509_EE_CERT_QES).getSsp();

    tspServiceListTsl.stream()
        .map(TspService::getTspServiceType)
        .map(
            tspServiceType ->
                tspServiceType.getServiceInformation().getServiceInformationExtensions())
        .filter(Objects::nonNull)
        .flatMap(
            serviceInformationExtensions -> serviceInformationExtensions.getExtension().stream())
        .map(ExtensionType::getContent)
        .flatMap(List::stream)
        .map(TucPki030VerifierTest::unwrapJaxbElement)
        .filter(AdditionalServiceInformationType.class::isInstance)
        .map(AdditionalServiceInformationType.class::cast)
        .filter(asi -> hasMatchingOcspUrlOverride(asi, aiaOcspUrl))
        .forEach(asi -> asi.setInformationValue(aiaOcspUrl + " " + newOcspUrl));
  }

  private static boolean hasMatchingOcspUrlOverride(
      final AdditionalServiceInformationType asi, final String aiaOcspUrl) {
    final String infoValue = asi.getInformationValue();
    return infoValue != null && infoValue.trim().startsWith(aiaOcspUrl + " ");
  }

  private static Object unwrapJaxbElement(final Object content) {
    return content instanceof final JAXBElement<?> jaxbElement ? jaxbElement.getValue() : content;
  }

  @BeforeAll
  void setup() {
    ocspResponderMock = OcspResponderMock.createAndStart(LOCAL_SSP_DIR, OCSP_HOST, null);
  }

  @AfterAll
  void tearDown() {
    ocspResponderMock.stop();
  }

  @BeforeEach
  void init() {

    tucPki030Verifier =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();

    ocspResponseValid =
        generateOcspResponse(
            VALID_X509_EE_CERT_QES,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            OcspRequestGenerator.generateNonceExtension());

    ocspResponseAltCa =
        generateOcspResponse(
            VALID_X509_EE_CERT_QES_ALT_CA,
            VALID_ISSUER_CERT_QES_ALT_CA,
            OcspTestConstants.getOcspSignerQes(),
            OcspRequestGenerator.generateNonceExtension());
  }

  @Test
  void performTucPki030Checks_whenOcspResponseIsValid_thenDoesNotThrow() {
    assertDoesNotThrow(
        () -> tucPki030Verifier.performTucPki030Checks(VALID_X509_EE_CERT_QES, ocspResponseValid));
  }

  @Test
  void performTucPki030Checks_whenEECertificateHasCaIssuersInAIA_thenDoesNotThrow()
      throws GemPkiException {
    final var admission =
        tucPki030Verifier.performTucPki030Checks(VALID_X509_EE_CERT_QES_ALT_CA, ocspResponseAltCa);
    assertThat(admission).isNotNull();
    assertThat(admission.getProfessionOids()).hasSize(1);
  }

  @Test
  void performTucPki030Checks_thenReturnAdmission() throws GemPkiException {
    final var admission =
        tucPki030Verifier.performTucPki030Checks(VALID_X509_EE_CERT_QES, ocspResponseValid);
    assertThat(admission).isNotNull();
    assertThat(admission.getProfessionOids()).hasSize(1);
  }

  @Test
  void performTucPki030Checks_when2admissons_thenReturn2Admissions() throws GemPkiException {
    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponse(
            VALID_X509_EE_CERT_QES_PSYCHO_TWO_ADMISSIONS,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            OcspRequestGenerator.generateNonceExtension());

    final Admission admission =
        tucPki030Verifier_.performTucPki030Checks(
            VALID_X509_EE_CERT_QES_PSYCHO_TWO_ADMISSIONS, ocspResponse);
    assertThat(admission.getProfessionOids()).hasSize(2);
  }

  @Test
  void performTucPki030Checks_whenMissingAdmission_thenThrowsGemPkiException()
      throws GemPkiException {

    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponse(
            X509_EE_CERT_QES_MISSING_ADMISSION,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            null);

    final Admission admission =
        tucPki030Verifier_.performTucPki030Checks(X509_EE_CERT_QES_MISSING_ADMISSION, ocspResponse);
    assertThat(admission.getProfessionOids()).isEmpty();
  }

  @Test
  void performTucPki030Checks_whenMissingOcspUrl_thenThrowsGemPkiException() {
    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes()).getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();

    assertThatThrownBy(
            () -> tucPki030Verifier_.performTucPki030Checks(X509_EE_CERT_QES_MISSING_OCSP_URL))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.TE_1026_SERVICESUPPLYPOINT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenMissingQcStatement_thenThrowsGemPkiException() {
    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes()).getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();

    assertThatThrownBy(
            () -> tucPki030Verifier_.performTucPki030Checks(X509_EE_CERT_QES_MISSING_QC_STATEMENT))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.TE_1048_QC_STATEMENT_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenWrongQcStatement_thenThrowsGemPkiException() {
    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes()).getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();

    assertThatThrownBy(
            () -> tucPki030Verifier_.performTucPki030Checks(X509_EE_CERT_QES_WRONG_QC_STATEMENT))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.TE_1048_QC_STATEMENT_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenMissingRole_thenThrowsGemPkiException() throws GemPkiException {
    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponse(
            X509_EE_CERT_QES_MISSING_ROLE,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            null);

    final Admission admission =
        tucPki030Verifier_.performTucPki030Checks(X509_EE_CERT_QES_MISSING_ROLE, ocspResponse);
    assertThat(admission).isNull();
  }

  @Test
  void performTucPki030Checks_whenWrongIssuer_thenThrowsGemPkiException() {
    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes()).getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();

    assertThatThrownBy(
            () -> tucPki030Verifier_.performTucPki030Checks(X509_EE_CERT_QES_WRONG_ISSUER))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenOcspResponseAndNonceAreValid_thenDoesNotThrow() {
    final Extension nonceExtension = OcspRequestGenerator.generateNonceExtension();
    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponse(
            VALID_X509_EE_CERT_QES,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            nonceExtension);

    assertDoesNotThrow(
        () ->
            tucPki030Verifier_.performTucPki030Checks(
                VALID_X509_EE_CERT_QES, nonceExtension, ocspResponse));
  }

  @Test
  void performTucPki030Checks_whenOcspResponseContainsMatchingNonce_thenDoesNotThrow() {
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    final TucPki030Verifier verifierWithNonce =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponse(
            VALID_X509_EE_CERT_QES,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            nonce);

    assertDoesNotThrow(
        () ->
            verifierWithNonce.performTucPki030Checks(VALID_X509_EE_CERT_QES, nonce, ocspResponse));
  }

  @Test
  void
      performTucPki030Checks_whenReferenceDateIsProvided_thenPassesReferenceDateAndGeneratedNonceToOcsp()
          throws GemPkiException {
    final Extension[] capturedNonce = new Extension[1];
    final ZonedDateTime[] capturedReferenceDate = new ZonedDateTime[1];
    final ZonedDateTime referenceDate =
        VALID_X509_EE_CERT_QES.getNotBefore().toInstant().atZone(ZoneOffset.UTC).plusDays(1);
    final TucPki030Verifier verifier = Mockito.spy(tucPki030Verifier);

    Mockito.doAnswer(
            invocation -> {
              capturedReferenceDate[0] = invocation.getArgument(2);
              capturedNonce[0] = invocation.getArgument(3);
              return null;
            })
        .when(verifier)
        .doOcspIfConfigured(
            Mockito.any(X509Certificate.class),
            Mockito.any(X509Certificate.class),
            Mockito.any(ZonedDateTime.class),
            Mockito.nullable(Extension.class),
            Mockito.nullable(OCSPResp.class));

    final Admission admission =
        verifier.performTucPki030Checks(VALID_X509_EE_CERT_QES, referenceDate);

    assertThat(admission).isNotNull();
    assertThat(capturedReferenceDate[0]).isEqualTo(referenceDate);
    assertThat(capturedNonce[0]).isNotNull();
    assertThat(capturedNonce[0].getExtnId()).isEqualTo(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
  }

  @Test
  void performTucPki030Checks_whenReferenceDateAndNonceAreProvided_thenPassesBothToOcsp()
      throws GemPkiException {
    final Extension[] capturedNonce = new Extension[1];
    final ZonedDateTime[] capturedReferenceDate = new ZonedDateTime[1];
    final ZonedDateTime referenceDate =
        VALID_X509_EE_CERT_QES.getNotBefore().toInstant().atZone(ZoneOffset.UTC).plusDays(1);
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    final TucPki030Verifier verifier = Mockito.spy(tucPki030Verifier);

    Mockito.doAnswer(
            invocation -> {
              capturedReferenceDate[0] = invocation.getArgument(2);
              capturedNonce[0] = invocation.getArgument(3);
              return null;
            })
        .when(verifier)
        .doOcspIfConfigured(
            Mockito.any(X509Certificate.class),
            Mockito.any(X509Certificate.class),
            Mockito.any(ZonedDateTime.class),
            Mockito.nullable(Extension.class),
            Mockito.nullable(OCSPResp.class));

    final Admission admission =
        verifier.performTucPki030Checks(VALID_X509_EE_CERT_QES, referenceDate, nonce);

    assertThat(admission).isNotNull();
    assertThat(capturedReferenceDate[0]).isEqualTo(referenceDate);
    assertThat(capturedNonce[0]).isSameAs(nonce);
  }

  @Test
  void
      performTucPki030Checks_whenOcspResponseIsMissingAndOnlineResponseMatchesNonce_thenDoesNotThrow() {
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    configureOcspResponderMockForOcspRequest(nonce);

    final TucPki030Verifier verifierWithOnlineOcsp =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl()))
            .build();

    assertDoesNotThrow(
        () -> verifierWithOnlineOcsp.performTucPki030Checks(VALID_X509_EE_CERT_QES, nonce));
  }

  @Test
  void
      performTucPki030Checks_whenOcspResponseIsMissingAndFactoryCreatesMatchingOnlineResponse_thenDoesNotThrow()
          throws GemPkiException {
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    configureOcspResponderMockForOcspRequest(nonce);
    final OcspTransceiverFactory ocspTransceiverFactory =
        Mockito.mock(OcspTransceiverFactory.class);
    Mockito.when(ocspTransceiverFactory.create(VALID_X509_EE_CERT_QES))
        .thenReturn(getOcspTransceiver(ocspResponderMock.getSspUrl()));

    final TucPki030Verifier verifierWithFactory =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .ocspTransceiverFactory(ocspTransceiverFactory)
            .build();

    assertDoesNotThrow(
        () -> verifierWithFactory.performTucPki030Checks(VALID_X509_EE_CERT_QES, nonce));
    Mockito.verify(ocspTransceiverFactory).create(VALID_X509_EE_CERT_QES);
  }

  /**
   * This test verifies that when the OCSP response is missing, the default factory creates a
   * matching online response with sending an OCSP request to the OCSP responder mock.
   */
  @Test
  void
      performTucPki030Checks_whenOcspResponseIsMissing_thenDefaultFactoryCreatesMatchingOnlineResponse()
          throws Exception {
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    configureOcspResponderMockForOcspRequest(nonce);
    final List<TspService> tspServiceListTsl = TestUtils.getDefaultTspServiceListNonQes();
    overwriteOcspUrlOverride(tspServiceListTsl, ocspResponderMock.getSspUrl());

    final TucPki030Verifier verifierWithDefaultFactory =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(tspServiceListTsl)
            .build();

    assertDoesNotThrow(
        () -> verifierWithDefaultFactory.performTucPki030Checks(VALID_X509_EE_CERT_QES, nonce));
  }

  @Test
  void
      performTucPki030Checks_whenProvidedOcspResponseIsInvalidAndOnlineResponseIsValid_thenDoesNotThrow() {
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    configureOcspResponderMockForOcspRequest(nonce);
    final ZonedDateTime referenceDate = GemLibPkiUtils.now().minusYears(10);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, nonce);
    final OCSPResp invalidOcspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerQes())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA);

    final TucPki030Verifier verifierWithFallback =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .ocspTransceiver(getOcspTransceiver(ocspResponderMock.getSspUrl()))
            .build();

    assertDoesNotThrow(
        () ->
            verifierWithFallback.performTucPki030Checks(
                VALID_X509_EE_CERT_QES, nonce, invalidOcspResponse));
  }

  @Test
  void
      performTucPki030Checks_whenProvidedOcspResponseIsInvalidAndFactoryCreatesValidOnlineResponse_thenDoesNotThrow()
          throws GemPkiException {
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    configureOcspResponderMockForOcspRequest(nonce);
    final ZonedDateTime referenceDate = GemLibPkiUtils.now().minusYears(10);
    final OcspTransceiverFactory ocspTransceiverFactory =
        Mockito.mock(OcspTransceiverFactory.class);
    Mockito.when(ocspTransceiverFactory.create(VALID_X509_EE_CERT_QES))
        .thenReturn(getOcspTransceiver(ocspResponderMock.getSspUrl()));

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA, nonce);
    final OCSPResp invalidOcspResponse =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerQes())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_QES, VALID_ISSUER_CERT_QES_DEFAULT_CA);

    final TucPki030Verifier verifierWithFactoryFallback =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .ocspTransceiverFactory(ocspTransceiverFactory)
            .build();

    assertDoesNotThrow(
        () ->
            verifierWithFactoryFallback.performTucPki030Checks(
                VALID_X509_EE_CERT_QES, nonce, invalidOcspResponse));
    Mockito.verify(ocspTransceiverFactory).create(VALID_X509_EE_CERT_QES);
  }

  @Test
  void performTucPki030Checks_whenProducedAtIsWithinCustomFutureTolerance_thenDoesNotThrow() {
    final Extension nonce = OcspRequestGenerator.generateNonceExtension();
    final ZonedDateTime referenceDate = ZonedDateTime.parse("2026-06-20T15:00:00Z");
    final ZonedDateTime producedAt = GemLibPkiUtils.now().plusSeconds(45);
    final ZonedDateTime nextUpdate = GemLibPkiUtils.now().plusMinutes(5);
    final ZonedDateTime thisUpdate = GemLibPkiUtils.now().minusSeconds(45);

    final TucPki030Verifier verifierWithNonce =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .ocspTimeToleranceProducedAtFutureMilliseconds(SECONDS_50_AS_MILLISECS)
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponseWithTimeStamps(
            VALID_X509_EE_CERT_QES,
            VALID_ISSUER_CERT_QES_DEFAULT_CA,
            OcspTestConstants.getOcspSignerQes(),
            nonce,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    assertDoesNotThrow(
        () ->
            verifierWithNonce.performTucPki030Checks(
                VALID_X509_EE_CERT_QES, referenceDate, nonce, ocspResponse));
  }

  @Test
  void performTucPki030Checks_whenNonceAndOcspResponseAreMissing_thenPassesGeneratedNonceToOcsp()
      throws GemPkiException {
    // Use a single-element array so the lambda can store the captured value for later assertions.
    final Extension[] capturedNonce = new Extension[1];
    // Spy on the real verifier so we can intercept the OCSP call without changing the surrounding
    // flow.
    final TucPki030Verifier verifier = Mockito.spy(tucPki030Verifier);
    Mockito.doAnswer(
            invocation -> {
              // The nonce is the 4th method argument (zero-based index 3).
              capturedNonce[0] = invocation.getArgument(3);
              return null;
            })
        .when(verifier)
        .doOcspIfConfigured(
            Mockito.any(X509Certificate.class),
            Mockito.any(X509Certificate.class),
            Mockito.any(ZonedDateTime.class),
            Mockito.nullable(Extension.class),
            Mockito.nullable(OCSPResp.class));

    assertDoesNotThrow(() -> verifier.performTucPki030Checks(VALID_X509_EE_CERT_QES));
    assertThat(capturedNonce[0]).isNotNull();
    assertThat(capturedNonce[0].getExtnId()).isEqualTo(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
  }

  @Test
  void performTucPki030Checks_whenNonceIsMissingAndOcspResponseIsPresent_thenPassesNullNonceToOcsp()
      throws GemPkiException {
    final Extension[] capturedNonce = new Extension[1];
    final TucPki030Verifier verifier = Mockito.spy(tucPki030Verifier);
    Mockito.doAnswer(
            invocation -> {
              capturedNonce[0] = invocation.getArgument(3);
              return null;
            })
        .when(verifier)
        .doOcspIfConfigured(
            Mockito.any(X509Certificate.class),
            Mockito.any(X509Certificate.class),
            Mockito.any(ZonedDateTime.class),
            Mockito.nullable(Extension.class),
            Mockito.nullable(OCSPResp.class));

    assertDoesNotThrow(
        () -> verifier.performTucPki030Checks(VALID_X509_EE_CERT_QES, ocspResponseValid));
    assertThat(capturedNonce[0]).isNull();
  }

  @Test
  void performTucPki030Checks_whenOcspSignerIssuerMatchesEeCertIssuer_thenDoesNotThrow() {
    final X509Certificate x509EeCert = VALID_X509_EE_CERT_QES_ALT_CA;

    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponse(
            x509EeCert, VALID_ISSUER_CERT_QES_ALT_CA, OcspTestConstants.getOcspSignerQes());
    assertDoesNotThrow(() -> tucPki030Verifier_.performTucPki030Checks(x509EeCert, ocspResponse));
  }

  @Test
  void performTucPki030Checks_whenAIA_contains_additional_CA_Issuer_thenDoesNotThrow() {
    final X509Certificate x509EeCert = VALID_X509_EE_CERT_QES_ALT_CA_CA_ISSUER;

    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getAdditionalCaDefaultTslUnsignedQes())
                    .getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponse(
            x509EeCert, VALID_ISSUER_CERT_QES_ALT_CA, OcspTestConstants.getOcspSignerQes());
    assertDoesNotThrow(() -> tucPki030Verifier_.performTucPki030Checks(x509EeCert, ocspResponse));
  }

  @Test
  void performTucPki030Checks_whenBNetzAVlDoesNotContainQesQualifiedCa_thenThrowsGemPkiException() {
    final X509Certificate x509EeCert = VALID_X509_EE_CERT_QES_ALT_CA;

    final TucPki030Verifier tucPki030Verifier_ =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes()).getTspServices())
            .tspServiceListTsl(TestUtils.getDefaultTspServiceListNonQes())
            .build();
    final OCSPResp ocspResponse =
        generateOcspResponse(
            x509EeCert, VALID_ISSUER_CERT_QES_ALT_CA, OcspTestConstants.getOcspSignerQes());
    assertThatThrownBy(() -> tucPki030Verifier_.performTucPki030Checks(x509EeCert, ocspResponse))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenCertificateContainsNoQcStatement_thenThrowsGemPkiException() {
    assertThatThrownBy(
            () ->
                tucPki030Verifier.performTucPki030Checks(
                    TestConstantsNonQes.VALID_X509_EE_CERT_SMCB))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.TE_1048_QC_STATEMENT_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenCertificateIsNotYetValidOrExpired_thenThrowsGemPkiException() {
    assertThatThrownBy(
            () -> tucPki030Verifier.performTucPki030Checks(X509_EE_CERT_QES_NOT_YET_VALID))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
    assertThatThrownBy(() -> tucPki030Verifier.performTucPki030Checks(X509_EE_CERT_QES_EXPIRED))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenCertificateKeyUsageIsMissingOrWrong_thenThrowsGemPkiException() {
    assertThatThrownBy(
            () -> tucPki030Verifier.performTucPki030Checks(X509_EE_CERT_QES_MISSING_KEY_USAGE))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));

    assertThatThrownBy(
            () -> tucPki030Verifier.performTucPki030Checks(X509_EE_CERT_QES_WRONG_KEY_USAGE))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenCertificateSignatureIsInvalid_thenThrowsGemPkiException() {
    assertThatThrownBy(
            () -> tucPki030Verifier.performTucPki030Checks(X509_EE_CERT_QES_SIGNATURE_ERROR))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.SE_1024_CERTIFICATE_NOT_VALID_MATH.getErrorMessage(PRODUCT_TYPE));
  }

  /**
   * Verifies that TUC_PKI_030 validates the QES CA chain against the certificate issuance date,
   * even if the BNetzA-VL marks the CA as withdrawn at validation time, as long as a matching
   * GRANTED history entry covers the certificate issuance date.
   */
  @Test
  void
      performTucPki030Checks_whenBNetzAVlTspIsWithdrawnAfterCertificateIssuanceButServiceHistoryShowsGranted_thenCertificateIsValid()
          throws GemPkiException {
    final X509Certificate eeCert = VALID_X509_EE_CERT_QES_ALT_CA;
    final List<TspService> tspServiceListBnetzAVl =
        new TslInformationProvider(
                TestUtils.getTslUnsigned(
                    FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_BUT_GRANTED_HISTORY))
            .getTspServices();
    final TspServiceSubset qesCaTspServiceSubset =
        new TspInformationProvider(tspServiceListBnetzAVl, PRODUCT_TYPE)
            .getIssuerTspServiceSubset(eeCert);
    final ZonedDateTime certificateIssuanceDate =
        eeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);
    final ZonedDateTime validationReferenceDate =
        qesCaTspServiceSubset.getStatusStartingTime().plusDays(1);

    final ZonedDateTime thisUpdate = validationReferenceDate;
    final ZonedDateTime producedAt = validationReferenceDate.plusSeconds(5);
    final ZonedDateTime nextUpdate = validationReferenceDate.plusMinutes(10);

    final TucPki030Verifier verifierWithWithdrawnBNetzAVl =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBnetzAVl)
            .build();
    final OCSPResp ocspResponse =
        TestUtils.generateOcspResponseWithTimeStamps(
            eeCert,
            VALID_ISSUER_CERT_QES_ALT_CA,
            OcspTestConstants.getOcspSignerQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    assertThat(qesCaTspServiceSubset.getServiceStatus()).isEqualTo(SVCSTATUS_WITHDRAWN);
    assertThat(certificateIssuanceDate).isBefore(qesCaTspServiceSubset.getStatusStartingTime());
    assertThat(validationReferenceDate).isAfter(qesCaTspServiceSubset.getStatusStartingTime());

    assertDoesNotThrow(
        () ->
            verifierWithWithdrawnBNetzAVl.performTucPki030Checks(
                eeCert, validationReferenceDate, ocspResponse));
  }

  /**
   * Counterpart to unit test
   * performTucPki030Checks_whenBNetzAVlTspIsWithdrawnAfterCertificateIssuanceButServiceHistoryShowsGranted_thenCertificateIsValid.
   * Here, the service history is missing, so the certificate should be considered invalid, even
   * though it was issued before the CA was withdrawn.
   */
  @Test
  void
      performTucPki030Checks_whenBNetzAVlTspIsWithdrawnAfterCertificateIssuanceAndServiceHistoryDoesNotExist_thenThrowsGemPkiException()
          throws GemPkiException {
    final X509Certificate eeCert = VALID_X509_EE_CERT_QES_ALT_CA;
    final List<TspService> tspServiceListBnetzAVl =
        new TslInformationProvider(
                TestUtils.getTslUnsigned(
                    FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_AND_WITHOUT_HISTORY))
            .getTspServices();
    final TspServiceSubset qesCaTspServiceSubset =
        new TspInformationProvider(tspServiceListBnetzAVl, PRODUCT_TYPE)
            .getIssuerTspServiceSubset(eeCert);
    final ZonedDateTime certificateIssuanceDate =
        eeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);
    final ZonedDateTime validationReferenceDate =
        qesCaTspServiceSubset.getStatusStartingTime().plusDays(1);

    final ZonedDateTime thisUpdate = validationReferenceDate;
    final ZonedDateTime producedAt = validationReferenceDate.plusSeconds(5);
    final ZonedDateTime nextUpdate = validationReferenceDate.plusMinutes(10);

    final TucPki030Verifier verifierWithWithdrawnBNetzAVl =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBnetzAVl)
            .build();
    final OCSPResp ocspResponse =
        TestUtils.generateOcspResponseWithTimeStamps(
            eeCert,
            VALID_ISSUER_CERT_QES_ALT_CA,
            OcspTestConstants.getOcspSignerQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    assertThat(qesCaTspServiceSubset.getServiceStatus()).isEqualTo(SVCSTATUS_WITHDRAWN);
    assertThat(certificateIssuanceDate).isBefore(qesCaTspServiceSubset.getStatusStartingTime());
    assertThat(validationReferenceDate).isAfter(qesCaTspServiceSubset.getStatusStartingTime());

    assertThatThrownBy(
            () ->
                verifierWithWithdrawnBNetzAVl.performTucPki030Checks(
                    eeCert, validationReferenceDate, ocspResponse))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED.getErrorMessage(PRODUCT_TYPE));
  }

  /**
   * Counterpart to unit test
   * performTucPki030Checks_whenBNetzAVlTspIsWithdrawnAfterCertificateIssuanceButServiceHistoryShowsGranted_thenCertificateIsValid.
   * Here, the service history has an entry, but it does not cover the certificate issuance date, so
   * the certificate should be considered invalid, even though it was issued before the CA was
   * withdrawn. (Another entry in the service history COULD make the certificate valid.)
   */
  @Test
  void
      performTucPki030Checks_whenBNetzAVlTspIsWithdrawnAfterCertificateIssuanceAndServiceHistoryEntryDoesNotMatchEeCertificate_thenThrowsGemPkiException()
          throws GemPkiException {
    final X509Certificate eeCert = VALID_X509_EE_CERT_QES_ALT_CA;
    final List<TspService> tspServiceListBnetzAVl =
        new TslInformationProvider(
                TestUtils.getTslUnsigned(
                    FILE_NAME_TSL_QES_DEFAULT_ADDITIONAL_CA_WITHDRAWN_HISTORYENTRY_DOES_NOT_MATCH_EE_CERTIFICATE))
            .getTspServices();
    final TspServiceSubset qesCaTspServiceSubset =
        new TspInformationProvider(tspServiceListBnetzAVl, PRODUCT_TYPE)
            .getIssuerTspServiceSubset(eeCert);
    final ZonedDateTime certificateIssuanceDate =
        eeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);
    final ZonedDateTime validationReferenceDate =
        qesCaTspServiceSubset.getStatusStartingTime().plusDays(1);

    final ZonedDateTime thisUpdate = validationReferenceDate;
    final ZonedDateTime producedAt = validationReferenceDate.plusSeconds(5);
    final ZonedDateTime nextUpdate = validationReferenceDate.plusMinutes(10);

    final TucPki030Verifier verifierWithWithdrawnBNetzAVl =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(tspServiceListBnetzAVl)
            .build();
    final OCSPResp ocspResponse =
        TestUtils.generateOcspResponseWithTimeStamps(
            eeCert,
            VALID_ISSUER_CERT_QES_ALT_CA,
            OcspTestConstants.getOcspSignerQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    assertThat(qesCaTspServiceSubset.getServiceStatus()).isEqualTo(SVCSTATUS_WITHDRAWN);
    assertThat(certificateIssuanceDate).isAfter(qesCaTspServiceSubset.getStatusStartingTime());
    assertThat(validationReferenceDate).isAfter(qesCaTspServiceSubset.getStatusStartingTime());

    assertThatThrownBy(
            () ->
                verifierWithWithdrawnBNetzAVl.performTucPki030Checks(
                    eeCert, validationReferenceDate, ocspResponse))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki030Checks_whenQesCaCertificateIsNotQualifiedInVl_thenThrowsGemPkiException() {
    final TucPki030Verifier verifierWithWrongVl =
        TucPki030Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceListBNetzAVl(
                new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes())
                    .getTspServices())
            .build();

    assertThatThrownBy(() -> verifierWithWrongVl.performTucPki030Checks(VALID_X509_EE_CERT_QES))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(
            ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED.getErrorMessage(PRODUCT_TYPE));
  }
}
