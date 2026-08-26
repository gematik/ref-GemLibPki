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

package de.gematik.pki.gemlibpki.commons.ocsp;

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.FILE_NAME_TSL_DEFAULT_NON_QES;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.FILE_NAME_TSL_DEFECT_NON_QES_OCSP_SIGNER_TSP_MISSING;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspTestConstants.TIMEOUT_DELTA_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspUtils.getBasicOcspResp;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator.ResponseAlgoBehavior;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.utils.P12Container;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

@Slf4j
class TucPki006OcspVerifierTest {

  private static List<TspService> tspServiceList;
  private static OCSPReq ocspReq;

  @BeforeAll
  public static void start() {
    ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    tspServiceList = TestUtils.getDefaultTspServiceListNonQes();
  }

  @Test
  void verifyOcspResponseChecks_whenCertificateStatusIsGood_thenDoesNotThrow() {
    assertDoesNotThrow(
        () -> genDefaultOcspVerifier().verifyOcspResponseChecks(GemLibPkiUtils.now()));
  }

  @Test
  void
      verifyOcspResponseChecks_whenOcspResponseStatusIsMalformedRequest_thenThrowsGemPkiException() {
    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .respStatus(OCSPRespStatus.MALFORMED_REQUEST)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();
    assertThatThrownBy(() -> verifier.verifyOcspResponseChecks(GemLibPkiUtils.now()))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1058_OCSP_STATUS_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyCertHash_whenCertHashMatchesEeCertificate_thenDoesNotThrow() {
    assertDoesNotThrow(() -> genDefaultOcspVerifier().verifyCertHash());
  }

  @Test
  void verifyCertHash_whenCertHashDoesNotMatchEeCertificate_thenThrowsGemPkiException() {

    assertThatThrownBy(
            () ->
                TucPki006OcspVerifier.builder()
                    .productType(PRODUCT_TYPE)
                    .tspServiceList(tspServiceList)
                    .eeCert(VALID_ISSUER_CERT_SMCB)
                    .ocspResponse(genDefaultOcspResp())
                    .build()
                    .verifyCertHash())
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1041_CERTHASH_MISMATCH.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyCertHash_whenCertHashExtensionIsMissing_thenThrowsGemPkiException() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .withCertHash(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    assertThatThrownBy(
            () ->
                TucPki006OcspVerifier.builder()
                    .productType(PRODUCT_TYPE)
                    .tspServiceList(tspServiceList)
                    .eeCert(VALID_X509_EE_CERT_SMCB)
                    .ocspResponse(ocspRespLocal)
                    .build()
                    .verifyCertHash())
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1040_CERTHASH_EXTENSION_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyCertHash_whenCertHashExtensionIsMissingAndEnforcementIsDisabled_thenDoesNotThrow() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .withCertHash(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    assertDoesNotThrow(
        () ->
            TucPki006OcspVerifier.builder()
                .productType(PRODUCT_TYPE)
                .tspServiceList(tspServiceList)
                .eeCert(VALID_X509_EE_CERT_SMCB)
                .ocspResponse(ocspRespLocal)
                .enforceCertHashCheck(false)
                .build()
                .verifyCertHash());
  }

  @Test
  void verifyMethods_whenRequiredArgumentsAreNull_thenThrowsOnNonNullParameter() {
    final TucPki006OcspVerifier.TucPki006OcspVerifierBuilder builder =
        TucPki006OcspVerifier.builder();

    assertNonNullParameter(() -> builder.productType(null), "productType");

    assertNonNullParameter(() -> builder.eeCert(null), "eeCert");

    assertNonNullParameter(() -> builder.ocspResponse(null), "ocspResponse");

    assertNonNullParameter(() -> builder.tspServiceList(null), "tspServiceList");

    final TucPki006OcspVerifier verifier = genDefaultOcspVerifier();

    assertNonNullParameter(() -> verifier.performTucPki006Checks(null), "referenceDate");

    assertNonNullParameter(() -> verifier.verifyOcspResponseChecks(null), "referenceDate");
  }

  private static OCSPResp genDefaultOcspResp() {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  private static OCSPResp genOcspRespWithIssuerCert() {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, CertificateStatus.GOOD);
  }

  private TucPki006OcspVerifier genDefaultOcspVerifier() {
    return TucPki006OcspVerifier.builder()
        .productType(PRODUCT_TYPE)
        .tspServiceList(tspServiceList)
        .eeCert(VALID_X509_EE_CERT_SMCB)
        .ocspResponse(genDefaultOcspResp())
        .build();
  }

  @Test
  void verifyOcspResponseSignature_whenSignatureMatchesOcspSigner_thenDoesNotThrow() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertDoesNotThrow(tucPki006OcspVerifier::verifyOcspResponseSignature);
  }

  @Test
  void verifyOcspResponseSignature_whenResponseContainsIssuerCertificate_thenDoesNotThrow() {

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(genOcspRespWithIssuerCert())
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertDoesNotThrow(tucPki006OcspVerifier::verifyOcspResponseSignature);
  }

  @Test
  void verifyOcspResponseSignature_whenSignatureIsInvalid_thenThrowsGemPkiException() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .validSignature(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyOcspResponseSignature)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1031_OCSP_SIGNATURE_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseSignature_whenOcspSignerIsMissingFromTsl_thenThrowsGemPkiException() {

    final List<TspService> tspServiceList =
        new TslInformationProvider(
                TestUtils.getTslUnsigned(FILE_NAME_TSL_DEFECT_NON_QES_OCSP_SIGNER_TSP_MISSING))
            .getTspServices();

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyOcspResponseSignature)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1030_OCSP_CERT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      verifyOcspResponseSignature_whenResponderUsesCertificateWithDifferentKey_thenThrowsGemPkiException() {
    final List<TspService> tspServiceList =
        new TslInformationProvider(TestUtils.getTslUnsigned(FILE_NAME_TSL_DEFAULT_NON_QES))
            .getTspServices();

    final P12Container signer = TestUtils.readP12nonQes("ocsp/eccDifferent-key.p12");

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(signer)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyOcspResponseSignature)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1030_OCSP_CERT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @ParameterizedTest
  @EnumSource(
      value = CertificateIdGeneration.class,
      names = {"VALID_CERTID"},
      mode = EnumSource.Mode.EXCLUDE)
  void verifyOcspResponseCertId_whenCertificateIdGenerationIsInvalid_thenThrowsGemPkiException(
      final CertificateIdGeneration certificateIdGeneration) {

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .certificateIdGeneration(certificateIdGeneration)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertThatThrownBy(tucPki006OcspVerifier::verifyOcspResponseCertId)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  private static Stream<Arguments> provideArgumentsForVerifyOcspResponseCertIdValid() {
    final List<AlgorithmIdentifier> algorithmIdentifiers =
        List.of(
            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1),
            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE),
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE));

    final List<Arguments> arguments = new ArrayList<>();

    for (final AlgorithmIdentifier algorithmIdentifier : algorithmIdentifiers) {
      for (final ResponseAlgoBehavior responseAlgoBehavior : ResponseAlgoBehavior.values()) {
        for (final boolean responseWithNullParameterHashAlgoOfCertId : List.of(false, true)) {
          arguments.add(
              Arguments.of(
                  algorithmIdentifier,
                  responseAlgoBehavior,
                  responseWithNullParameterHashAlgoOfCertId));
        }
      }
    }
    return arguments.stream();
  }

  @ParameterizedTest
  @MethodSource("provideArgumentsForVerifyOcspResponseCertIdValid")
  void verifyOcspResponseCertId_whenCertificateIdMatchesAcrossSupportedAlgorithms_thenDoesNotThrow(
      final AlgorithmIdentifier requestAlgorithmIdentifier,
      final ResponseAlgoBehavior responseAlgoBehavior,
      final boolean responseWithNullParameterHashAlgoOfCertId) {

    log.info(
        """

            requestAlgorithmIdentifier: {} {}
            responseAlgoBehavior: {}
            responseWithNullParameterHashAlgoOfCertId: {}
            """,
        requestAlgorithmIdentifier.getAlgorithm().getId(),
        requestAlgorithmIdentifier.getParameters(),
        responseAlgoBehavior,
        responseWithNullParameterHashAlgoOfCertId);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, requestAlgorithmIdentifier);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .responseAlgoBehavior(responseAlgoBehavior)
            .withNullParameterHashAlgoOfCertId(responseWithNullParameterHashAlgoOfCertId)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspResp)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertDoesNotThrow(tucPki006OcspVerifier::verifyOcspResponseCertId);
  }

  @Test
  void
      verifyOcspResponseChecks_whenCertificateStatusIsRevokedBeforeReferenceDate_thenThrowsGemPkiException() {

    final ZonedDateTime revokedDate = GemLibPkiUtils.now().minusMinutes(10);

    final int revokedReason = CRLReason.aACompromise;

    final CertificateStatus revokedStatus =
        new RevokedStatus(java.sql.Date.from(revokedDate.toInstant()), revokedReason);

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, revokedStatus);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertThatThrownBy(() -> tucPki006OcspVerifier.verifyOcspResponseChecks(GemLibPkiUtils.now()))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SW_1047_CERT_REVOKED.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      verifyOcspResponseChecks_whenCertificateStatusIsRevokedAfterReferenceDate_thenDoesNotThrow() {
    final ZonedDateTime revokedDate = GemLibPkiUtils.now().plusMinutes(10);

    final CertificateStatus revokedStatus =
        new RevokedStatus(java.sql.Date.from(revokedDate.toInstant()), CRLReason.aACompromise);

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, revokedStatus);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertDoesNotThrow(() -> tucPki006OcspVerifier.verifyOcspResponseChecks(GemLibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseChecks_whenCertificateStatusIsUnknown_thenThrowsGemPkiException() {

    final CertificateStatus unknownStatus = new UnknownStatus();

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, unknownStatus);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .build();

    assertThatThrownBy(() -> tucPki006OcspVerifier.verifyOcspResponseChecks(GemLibPkiUtils.now()))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TW_1044_CERT_UNKNOWN.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void generate_whenResponderIdTypeIsByName_thenSetsResponderSubjectName() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .responderIdType(ResponderIdType.BY_NAME)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final BasicOCSPResp basicOcspResp = getBasicOcspResp(ocspResp);
    final RespID respId = basicOcspResp.getResponderId();
    final ResponderID responderId = respId.toASN1Primitive();

    final X500Name ocspRespResponderIdName = responderId.getName();
    final X500Name subjectDn =
        new X500Name(
            OcspTestConstants.getOcspSignerEccNonQes()
                .getCertificate()
                .getSubjectX500Principal()
                .getName());

    assertThat(ocspRespResponderIdName).isEqualTo(subjectDn);
  }

  @Test
  void verifyOcspResponseChecks_whenThisUpdateIsAtFutureToleranceBoundary_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime thisUpdate =
        referenceDate.plus(OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS, ChronoUnit.MILLIS);
    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(thisUpdate)
            .producedAt(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void verifyOcspResponseChecks_whenThisUpdateIsInPast_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(referenceDate.minusYears(1))
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void verifyOcspResponseChecks_whenThisUpdateExceedsFutureTolerance_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime thisUpdate =
        referenceDate.plus(
            OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS,
            ChronoUnit.MILLIS);
    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(thisUpdate)
            .producedAt(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertThatThrownBy(() -> verifier.verifyOcspResponseChecks(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      verifyOcspResponseChecks_whenProducedAtIsAtDefaultFutureToleranceBoundary_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime producedAt =
        referenceDate.plus(
            OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(producedAt)
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    // Instantiation of TucPki006OcspVerifier with default value of OCSP time tolerance
    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void verifyOcspResponseChecks_whenProducedAtIsWithinCustomFutureTolerance_thenDoesNotThrow() {
    final int SECONDS_10 = 10000;
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime producedAt = referenceDate.plus(SECONDS_10, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(producedAt)
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtFutureMilliseconds(SECONDS_10)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void
      verifyOcspResponseChecks_whenProducedAtExceedsDefaultFutureTolerance_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime producedAt =
        referenceDate.plus(
            OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS,
            ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(producedAt)
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    // Instantiation of TucPki006OcspVerifier with default value of OCSP time tolerance
    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertThatThrownBy(() -> verifier.verifyOcspResponseChecks(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      verifyOcspResponseChecks_whenProducedAtExceedsCustomFutureTolerance_thenThrowsGemPkiException() {
    final int SECONDS_10 = 10000;
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime producedAt =
        referenceDate.plus(SECONDS_10 + TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(producedAt)
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtFutureMilliseconds(SECONDS_10)
            .build();

    assertThatThrownBy(() -> verifier.verifyOcspResponseChecks(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseChecks_whenProducedAtIsWithinDefaultPastTolerance_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime producedAt =
        referenceDate.minus(
            OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS - TIMEOUT_DELTA_MILLISECONDS,
            ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(producedAt)
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    // Instantiation of TucPki006OcspVerifier with default value of OCSP time tolerance
    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void verifyOcspResponseChecks_whenProducedAtIsWithinCustomPastTolerance_thenDoesNotThrow() {
    final int SECONDS_10 = 10000;
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime producedAt =
        referenceDate.minus(SECONDS_10 - TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(producedAt)
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtPastMilliseconds(SECONDS_10)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void
      verifyOcspResponseChecks_whenProducedAtExceedsDefaultPastTolerance_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime producedAt =
        referenceDate.minus(
            OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS,
            ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(producedAt)
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    // Instantiation of TucPki006OcspVerifier with default value of OCSP time tolerance
    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertThatThrownBy(() -> verifier.verifyOcspResponseChecks(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      verifyOcspResponseChecks_whenProducedAtExceedsCustomPastTolerance_thenThrowsGemPkiException() {
    final int SECONDS_10 = 10000;
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime producedAt =
        referenceDate.minus(SECONDS_10 + TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .thisUpdate(producedAt)
            .producedAt(producedAt)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtPastMilliseconds(SECONDS_10)
            .build();

    assertThatThrownBy(() -> verifier.verifyOcspResponseChecks(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseChecks_whenNextUpdateExceedsPastTolerance_thenThrowsGemPkiException() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime nextUpdate =
        referenceDate.minus(
            OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS,
            ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .nextUpdate(nextUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertThatThrownBy(() -> verifier.verifyOcspResponseChecks(referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyOcspResponseChecks_whenNextUpdateIsWithinPastTolerance_thenDoesNotThrow() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final ZonedDateTime nextUpdate =
        referenceDate.minus(
            OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS - TIMEOUT_DELTA_MILLISECONDS,
            ChronoUnit.MILLIS);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .nextUpdate(nextUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void verifyOcspResponseChecks_whenNextUpdateIsInFuture_thenDoesNotThrow() {

    final ZonedDateTime nextUpdate = ZonedDateTime.now().plusYears(1);
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .nextUpdate(nextUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void verifyOcspResponseChecks_whenNextUpdateIsMissing_thenDoesNotThrow() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now();
    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .nextUpdate(null)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyOcspResponseChecks(referenceDate));
  }

  @Test
  void performTucPki006Checks_whenOfflineOcspResponseUsesCurrentReferenceDate_thenDoesNotThrow() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now();

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceListNonQes())
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.performTucPki006Checks());
  }

  @Test
  void performTucPki006Checks_whenOfflineOcspResponseUsesProvidedReferenceDate_thenDoesNotThrow() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now().minusYears(10);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceListNonQes())
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.performTucPki006Checks(referenceDate));
  }

  @Test
  void
      performTucPki006Checks_whenOfflineOcspResponseIsExpiredWithoutReferenceDate_thenThrowsGemPkiException() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now().minusYears(10);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceListNonQes())
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertThatThrownBy(verifier::performTucPki006Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  private Pair<OCSPResp, TucPki006OcspVerifier> getPairForMocks() {
    return getPairForMocks(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  private Pair<OCSPResp, TucPki006OcspVerifier> getPairForMocks(
      @NonNull final X509Certificate eeCert, @NonNull final X509Certificate issuerCert) {
    final ZonedDateTime referenceDate = GemLibPkiUtils.now();

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, eeCert, issuerCert);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceListNonQes())
            .eeCert(eeCert)
            .ocspResponse(ocspResp)
            .build();
    return Pair.of(ocspResp, verifier);
  }

  @Test
  void
      verifyOcspResponseSignature_whenBasicOcspResponseSignatureValidationThrowsOcspException_thenThrowsGemPkiRuntimeException()
          throws OCSPException {

    final Pair<OCSPResp, TucPki006OcspVerifier> pair = getPairForMocks();

    final OCSPResp ocspResp = pair.getLeft();
    final TucPki006OcspVerifier verifier = pair.getRight();

    final BasicOCSPResp basicOcspResp = getBasicOcspResp(ocspResp);
    final BasicOCSPResp basicOcspRespSpy = Mockito.spy(basicOcspResp);
    Mockito.doThrow(OCSPException.class).when(basicOcspRespSpy).isSignatureValid(Mockito.any());

    try (final MockedStatic<OcspUtils> ocspUtils = Mockito.mockStatic(OcspUtils.class)) {
      ocspUtils.when(() -> OcspUtils.getBasicOcspResp(Mockito.any())).thenReturn(basicOcspRespSpy);
      assertThatThrownBy(verifier::verifyOcspResponseSignature)
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Fehler beim Lesen des OCSP Signer Zertifikates aus der OCSP Response.");
    }
  }

  @Test
  void
      verifyOcspResponseSignature_whenBasicOcspResponseContainsNoCertificates_thenThrowsGemPkiRuntimeException() {

    final Pair<OCSPResp, TucPki006OcspVerifier> pair = getPairForMocks();

    final OCSPResp ocspResp = pair.getLeft();
    final TucPki006OcspVerifier verifier = pair.getRight();

    final BasicOCSPResp basicOcspResp = getBasicOcspResp(ocspResp);
    final BasicOCSPResp basicOcspRespSpy = Mockito.spy(basicOcspResp);
    Mockito.doReturn(new X509CertificateHolder[] {}).when(basicOcspRespSpy).getCerts();

    try (final MockedStatic<OcspUtils> ocspUtils = Mockito.mockStatic(OcspUtils.class)) {
      ocspUtils.when(() -> OcspUtils.getBasicOcspResp(Mockito.any())).thenReturn(basicOcspRespSpy);
      assertThatThrownBy(verifier::verifyOcspResponseSignature)
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Keine Zertifikate in der OCSP-Response gefunden.");
    }
  }

  @Test
  void
      verifyOcspResponseSignature_whenSignerCertificateConversionFails_thenThrowsGemPkiRuntimeException() {

    final Pair<OCSPResp, TucPki006OcspVerifier> pair = getPairForMocks();

    final TucPki006OcspVerifier verifier = pair.getRight();

    try (final MockedConstruction<JcaX509CertificateConverter> ignored =
        Mockito.mockConstruction(
            JcaX509CertificateConverter.class,
            (mock, context) ->
                Mockito.when(mock.getCertificate(Mockito.any()))
                    .thenThrow(new CertificateException()))) {
      assertThatThrownBy(verifier::verifyOcspResponseSignature)
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Fehler beim Lesen des OCSP Signer Zertifikates aus der OCSP Response.");
    }
  }

  @Test
  void verifyOcspResponseSignature_whenSignerCertificateEncodingFails_thenThrowsGemPkiException()
      throws CertificateEncodingException {

    final Pair<OCSPResp, TucPki006OcspVerifier> pair = getPairForMocks();

    final TucPki006OcspVerifier verifier = pair.getRight();

    final X509Certificate x509CertSpy = Mockito.spy(VALID_X509_EE_CERT_SMCB);
    Mockito.doThrow(CertificateEncodingException.class).when(x509CertSpy).getEncoded();

    try (final MockedConstruction<JcaX509CertificateConverter> ignored =
        Mockito.mockConstruction(
            JcaX509CertificateConverter.class,
            (mock, context) ->
                Mockito.when(mock.getCertificate(Mockito.any())).thenReturn(x509CertSpy))) {
      assertThatThrownBy(verifier::verifyOcspResponseSignature)
          .isInstanceOf(GemPkiException.class)
          .hasMessage(ErrorCode.SE_1031_OCSP_SIGNATURE_ERROR.getErrorMessage(PRODUCT_TYPE));
    }
  }

  @Test
  void verifyCertHash_whenEeCertificateEncodingFails_thenThrowsGemPkiRuntimeException()
      throws CertificateEncodingException {

    final X509Certificate x509CertSpy = Mockito.spy(VALID_X509_EE_CERT_SMCB);

    final Pair<OCSPResp, TucPki006OcspVerifier> pair =
        getPairForMocks(x509CertSpy, VALID_ISSUER_CERT_SMCB);
    final TucPki006OcspVerifier verifier = pair.getRight();

    Mockito.doThrow(CertificateEncodingException.class).when(x509CertSpy).getEncoded();

    try (final MockedConstruction<JcaX509CertificateConverter> ignored =
        Mockito.mockConstruction(
            JcaX509CertificateConverter.class,
            (mock, context) ->
                Mockito.when(mock.getCertificate(Mockito.any())).thenReturn(x509CertSpy))) {
      assertThatThrownBy(verifier::verifyCertHash)
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Cannot convert certificate to bytes.");
    }
  }
}
