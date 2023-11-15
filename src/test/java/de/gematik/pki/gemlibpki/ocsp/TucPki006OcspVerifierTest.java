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

package de.gematik.pki.gemlibpki.ocsp;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_RSA_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.TIMEOUT_DELTA_MILLISECONDS;
import static de.gematik.pki.gemlibpki.ocsp.OcspUtils.getBasicOcspResp;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponderIdType;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.ResponseAlgoBehavior;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.TestUtils;
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_X509_EE_CERT_SMCB)
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
  void verifyCertHashInvalid() {

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
  void verifyCertHashMissing() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
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
  void verifyCertHashMissingNotEnforceCertHashCheck() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
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
  void nonNullTests() {
    final TucPki006OcspVerifier.TucPki006OcspVerifierBuilder builder =
        TucPki006OcspVerifier.builder();

    assertNonNullParameter(() -> builder.productType(null), "productType");

    assertNonNullParameter(() -> builder.eeCert(null), "eeCert");

    assertNonNullParameter(() -> builder.ocspResponse(null), "ocspResponse");

    assertNonNullParameter(() -> builder.tspServiceList(null), "tspServiceList");

    final TucPki006OcspVerifier verifier = genDefaultOcspVerifier();

    assertNonNullParameter(() -> verifier.performTucPki006Checks(null), "referenceDate");

    assertNonNullParameter(() -> verifier.verifyStatus(null), "referenceDate");

    assertNonNullParameter(() -> verifier.verifyThisUpdate(null), "referenceDate");

    assertNonNullParameter(() -> verifier.verifyProducedAt(null), "referenceDate");

    assertNonNullParameter(() -> verifier.verifyNextUpdate(null), "referenceDate");
  }

  private static OCSPResp genDefaultOcspResp() {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEcc())
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
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
  void verifyOcspSignatureValid() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
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
  void verifyOcspSignatureInvalid() {
    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
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
  void verifyOcspSignerMissing() {

    final List<TspService> tspServiceList =
        new TslInformationProvider(TestUtils.getTslUnsigned(FILE_NAME_TSL_RSA_DEFAULT))
            .getTspServices();

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
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
  void verifyOcspSignerMissingDifferentKey() {
    final List<TspService> tspServiceList =
        new TslInformationProvider(TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT))
            .getTspServices();

    final P12Container signer = TestUtils.readP12("ocsp/eccDifferent-key.p12");

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
  void verifyOcspResponseCertIdInvalid(final CertificateIdGeneration certificateIdGeneration) {

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
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
  void verifyOcspResponseCertIdValid(
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
            .signer(OcspTestConstants.getOcspSignerEcc())
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
  void verifyOcspResponseCertStatusRevoked() {

    final ZonedDateTime revokedDate = GemLibPkiUtils.now().minusMinutes(10);

    final int revokedReason = CRLReason.aACompromise;

    final CertificateStatus revokedStatus =
        new RevokedStatus(java.sql.Date.from(revokedDate.toInstant()), revokedReason);

    final OCSPResp ocspRespLocal =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, revokedStatus);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, unknownStatus);

    final TucPki006OcspVerifier tucPki006OcspVerifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .ocspResponse(ocspRespLocal)
            .eeCert(VALID_X509_EE_CERT_SMCB)
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyThisUpdate(GemLibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseThisUpdateAnyPast() {

    final ZonedDateTime thisUpdate = ZonedDateTime.now().minusYears(1);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .thisUpdate(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyThisUpdate(GemLibPkiUtils.now()));
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    final ZonedDateTime now = GemLibPkiUtils.now();
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyProducedAt(GemLibPkiUtils.now()));
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    final ZonedDateTime now = GemLibPkiUtils.now();
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyProducedAt(GemLibPkiUtils.now()));
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    final ZonedDateTime now = GemLibPkiUtils.now();
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    final ZonedDateTime now = GemLibPkiUtils.now();
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
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyNextUpdate(GemLibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseNextUpdateAnyFuture() {

    final ZonedDateTime nextUpdate = ZonedDateTime.now().plusYears(1);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .nextUpdate(nextUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyNextUpdate(GemLibPkiUtils.now()));
  }

  @Test
  void verifyOcspResponseNextUpdateNotSet() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .nextUpdate(null)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .eeCert(VALID_ISSUER_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.verifyNextUpdate(GemLibPkiUtils.now()));
  }

  @Test
  void verifyOfflineOcspResponse() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now();

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceList())
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.performTucPki006Checks());
  }

  @Test
  void verifyOfflineOcspResponseWithReferenceDate() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now().minusYears(10);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceList())
            .eeCert(VALID_X509_EE_CERT_SMCB)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.performTucPki006Checks(referenceDate));
  }

  @Test
  void verifyOfflineOcspResponseNoReferenceDate() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now().minusYears(10);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceList())
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
            .signer(OcspTestConstants.getOcspSignerEcc())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate)
            .build()
            .generate(ocspReq, eeCert, issuerCert);

    final TucPki006OcspVerifier verifier =
        TucPki006OcspVerifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(TestUtils.getDefaultTspServiceList())
            .eeCert(eeCert)
            .ocspResponse(ocspResp)
            .build();
    return Pair.of(ocspResp, verifier);
  }

  @Test
  void verifyOcspResponseSignature_MockExceptionSignatureResponse() throws OCSPException {

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
          .hasMessage("Interner Fehler beim verifizieren der Ocsp Response Signatur.");
    }
  }

  @Test
  void verifyOcspResponseSignature_MockExceptionNotUniqueCertHolderInBasicOcspResp() {

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
          .hasMessage("Nicht genau 1 Zertifikat in OCSP-Response gefunden.");
    }
  }

  @Test
  void verifyOcspResponseSignature_MockExceptionJcaX509CertificateConverter() {

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
          .hasMessage("Fehler beim lesen der OCSP Signer Zertifikates aus der OCSP Response.");
    }
  }

  @Test
  void verifyOcspResponseSignature_MockExceptionCertGetEncoded()
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
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Fehler beim lesen des OCSP Signers aus der Response.");
    }
  }

  @Test
  void verifyCertHash_MockCertificateEncodingException() throws CertificateEncodingException {

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
          .hasMessage("Cannot convert certificate to bytes");
    }
  }
}
