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

package de.gematik.pki.gemlibpki.ocsp;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_RSA_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.TIMEOUT_DELTA_MILLISECONDS;
import static de.gematik.pki.gemlibpki.ocsp.OcspTestConstants.P12_PASSWORD;
import static de.gematik.pki.gemlibpki.ocsp.OcspUtils.getBasicOcspResp;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.utils.CertificateProvider;
import de.gematik.pki.gemlibpki.utils.GemlibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class TucPki006OcspVerifierTest {

  private static List<TspService> tspServiceList;
  private static X509Certificate VALID_X509_EE_CERT;
  private static X509Certificate VALID_X509_ISSUER_CERT;
  private static OCSPReq ocspReq;

  @BeforeAll
  public static void start() {
    VALID_X509_EE_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
    VALID_X509_ISSUER_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
    ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);

    tspServiceList = TestUtils.getDefaultTspServiceList();
  }

  @Test
  void verifyCertificateStatusGood() {
    assertDoesNotThrow(() -> genDefaultOcspVerifier().verifyStatus());
  }

  @Test
  void verifyCertificateStatusNotGood() {
    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .respStatus(OCSPRespStatus.MALFORMED_REQUEST)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);
    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT)
            .ocspResponse(ocspResp)
            .build();
    assertThatThrownBy(verifier::verifyStatus)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1058_OCSP_STATUS_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyCertHashValid() {
    assertDoesNotThrow(() -> genDefaultOcspVerifier().verifyCertHash());
  }

  @Test
  void verifyCertHashInValid() {

    assertThatThrownBy(
            () ->
                TucPki006OcspVerifier.builder()
                    .productType(PRODUCT_TYPE)
                    .tspServiceList(tspServiceList)
                    .eeCert(VALID_X509_ISSUER_CERT)
                    .ocspResponse(genDefaultOcspResp())
                    .build()
                    .verifyCertHash())
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1041_CERTHASH_MISMATCH.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyCertHashMissing() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerRsa())
            .withCertHash(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);
    assertThatThrownBy(
            () ->
                TucPki006OcspVerifier.builder()
                    .productType(PRODUCT_TYPE)
                    .tspServiceList(tspServiceList)
                    .eeCert(VALID_X509_EE_CERT)
                    .ocspResponse(ocspRespLocal)
                    .build()
                    .verifyCertHash())
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1040_CERTHASH_EXTENSION_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyCertHashMissingNotEnforceCertHashCheck() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerRsa())
            .withCertHash(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    assertDoesNotThrow(
        () ->
            TucPki006OcspVerifier.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceList(tspServiceList)
                .eeCert(VALID_X509_EE_CERT)
                .ocspResponse(ocspRespLocal)
                .enforceCertHashCheck(false)
                .build()
                .verifyCertHash());
  }

  @Test
  void nonNullTests() {
    final TucPki006OcspVerifier.TucPki006OcspVerifierBuilder builder =
        TucPki006OcspVerifier.builder();

    assertThatThrownBy(() -> builder.productType(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("productType is marked non-null but is null");

    assertThatThrownBy(() -> builder.eeCert(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("eeCert is marked non-null but is null");

    assertThatThrownBy(() -> builder.ocspResponse(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("ocspResponse is marked non-null but is null");

    assertThatThrownBy(() -> builder.tspServiceList(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tspServiceList is marked non-null but is null");

    final TucPki006OcspVerifier verifier = genDefaultOcspVerifier();
    final ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
    assertThatThrownBy(() -> verifier.performOcspChecks(null, now))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("ocspReq is marked non-null but is null");

    final OCSPReq req =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);
    assertThatThrownBy(() -> verifier.performOcspChecks(req, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("referenceDate is marked non-null but is null");

    assertThatThrownBy(() -> verifier.verifyStatus(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("referenceDate is marked non-null but is null");

    assertThatThrownBy(() -> verifier.verifyOcspResponseCertId(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("ocspReq is marked non-null but is null");
  }

  private static OCSPResp genDefaultOcspResp() {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerRsa())
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT);
  }

  private TucPki006OcspVerifier genDefaultOcspVerifier() {
    return TucPki006OcspVerifier.builder()
        .productType(PRODUCT_TYPE)
        .tspServiceList(tspServiceList)
        .eeCert(VALID_X509_EE_CERT)
        .ocspResponse(genDefaultOcspResp())
        .build();
  }

  @Test
  void verifyOcspSignatureValid() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT)
            .build();

    assertDoesNotThrow(tucPki006OcspVerifier::verifyOcspResponseSignature);
  }

  @Test
  void verifyOcspSignatureInvalid() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .validSignature(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyOcspResponseSignature)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1031_OCSP_SIGNATURE_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspSspMissing() {

    final String tslMissingSspFilename = "tsls/ecc/defect/TSL_defect_altCA_missingSsp.xml";
    final List<TspService> badTspServiceList =
        new TslInformationProvider(TestUtils.getTsl(tslMissingSspFilename)).getTspServices();

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerRsa())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(badTspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyOcspResponseSignature)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1030_OCSP_CERT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspSignerMissing() {

    final List<TspService> tspServiceList =
        new TslInformationProvider(TestUtils.getTsl(FILE_NAME_TSL_RSA_DEFAULT)).getTspServices();

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyOcspResponseSignature)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1030_OCSP_CERT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspSignerMissingDifferentKey() {

    final List<TspService> tspServiceList =
        new TslInformationProvider(TestUtils.getTsl(FILE_NAME_TSL_RSA_DEFAULT)).getTspServices();

    final P12Container signer =
        P12Reader.getContentFromP12(
            Path.of("src/test/resources/certificates/ocsp/eccDifferent-key.p12"), P12_PASSWORD);

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(signer)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyOcspResponseSignature)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1030_OCSP_CERT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseCertId() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .validCertId(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT)
            .build();

    assertThatThrownBy(() -> tucPki006OcspVerifier.verifyOcspResponseCertId(ocspReq))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseCertStatusRevoked() {

    final ZonedDateTime revokedDate = GemlibPkiUtils.now().minusMinutes(10);

    final int revokedReason = CRLReason.aACompromise;

    final CertificateStatus revokedStatus =
        new RevokedStatus(java.sql.Date.from(revokedDate.toInstant()), revokedReason);

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT, revokedStatus);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyStatus)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SW_1047_CERT_REVOKED.getErrorMessage(PRODUCT_TYPE));

    assertDoesNotThrow(() -> tucPki006OcspVerifier.verifyStatus(revokedDate.minusMinutes(10)));
  }

  @Test
  void verifyOcspResponseCertStatusUnknown() {

    final CertificateStatus unknownStatus = new UnknownStatus();

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT, unknownStatus);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyStatus)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TW_1044_CERT_UNKNOWN.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseCertResponderIdByName() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .responderIdType(ResponderIdType.BY_NAME)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final BasicOCSPResp basicOcspResp = getBasicOcspResp(ocspResp);
    final RespID respId = basicOcspResp.getResponderId();
    final ResponderID responderId = respId.toASN1Primitive();

    final X500Name ocspRespResponderIdName = responderId.getName();
    final X500Name subjectDn =
        new X500Name(
            OcspTestConstants.getOcspSignerEcc()
                .getCertificate()
                .getSubjectX500Principal()
                .getName());

    assertThat(ocspRespResponderIdName).isEqualTo(subjectDn);
  }

  @Test
  void verifyOcspResponseThisUpdateWithinToleranceFuture() {

    final ZonedDateTime thisUpdate =
        ZonedDateTime.now().plus(OCSP_TIME_TOLERANCE_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .thisUpdate(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyThisUpdate(GemlibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseThisUpdateAnyPast() {

    final ZonedDateTime thisUpdate = ZonedDateTime.now().minusYears(1);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .thisUpdate(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyThisUpdate(GemlibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseThisUpdateOutOfToleranceFuture() {

    final ZonedDateTime thisUpdate =
        ZonedDateTime.now()
            .plus(OCSP_TIME_TOLERANCE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .thisUpdate(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    final ZonedDateTime now = GemlibPkiUtils.now();
    assertThatThrownBy(() -> verifier.verifyThisUpdate(now))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseProducedAtWithinToleranceFuture() {

    final ZonedDateTime producedAt =
        ZonedDateTime.now().plus(OCSP_TIME_TOLERANCE_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyProducedAt(GemlibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseProducedAtOutOfTolerancePast() {

    final ZonedDateTime producedAt =
        ZonedDateTime.now()
            .minus(
                OCSP_TIME_TOLERANCE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    final ZonedDateTime now = GemlibPkiUtils.now();
    assertThatThrownBy(() -> verifier.verifyProducedAt(now))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseProducedAtWithinTolerancePast() {

    final ZonedDateTime producedAt =
        ZonedDateTime.now()
            .minus(
                OCSP_TIME_TOLERANCE_MILLISECONDS - TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyProducedAt(GemlibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseProducedAtOutOfToleranceFuture() {

    final ZonedDateTime producedAt =
        ZonedDateTime.now()
            .plus(OCSP_TIME_TOLERANCE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    final ZonedDateTime now = GemlibPkiUtils.now();
    assertThatThrownBy(() -> verifier.verifyProducedAt(now))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseNextUpdateOutOfTolerancePast() {

    final ZonedDateTime nextUpdate =
        ZonedDateTime.now()
            .minus(
                OCSP_TIME_TOLERANCE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .nextUpdate(nextUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    final ZonedDateTime now = GemlibPkiUtils.now();
    assertThatThrownBy(() -> verifier.verifyNextUpdate(now))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseNextUpdateWithinTolerancePast() {

    final ZonedDateTime nextUpdate =
        ZonedDateTime.now()
            .minus(
                OCSP_TIME_TOLERANCE_MILLISECONDS - TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .nextUpdate(nextUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyNextUpdate(GemlibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseNextUpdateAnyFuture() {

    final ZonedDateTime nextUpdate = ZonedDateTime.now().plusYears(1);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .nextUpdate(nextUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyNextUpdate(GemlibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseNextUpdateNotSet() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .nextUpdate(null)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_ISSUER_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyNextUpdate(GemlibPkiUtils.now()));
  }

  @Test
  void verifyOfflineOcspResponseWithReferenceDate() {

    final ZonedDateTime referenceDate = GemlibPkiUtils.now().minusYears(10);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceList())
            .eeCert(VALID_X509_EE_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.performOcspChecks(ocspReq, referenceDate));
  }

  @Test
  void verifyOfflineOcspResponseNoReferenceDate() {

    final ZonedDateTime referenceDate = GemlibPkiUtils.now().minusYears(10);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceList())
            .eeCert(VALID_X509_EE_CERT)
            .ocspResponse(ocspResp)
            .build();

    assertThatThrownBy(() -> verifier.performOcspChecks(ocspReq))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }
}
