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
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspTestConstants.TIMEOUT_DELTA_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator.ResponseAlgoBehavior;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

class OcspVerificationTest {

  private static OCSPReq ocspReq;

  @BeforeAll
  static void start() {
    ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  @Test
  void verifyStatus_whenCertificateStatusIsGood_thenDoesNotThrow() {
    assertDoesNotThrow(
        () ->
            OcspVerification.verifyStatus(PRODUCT_TYPE, genDefaultOcspResp(), ZonedDateTime.now()));
  }

  @ParameterizedTest
  @EnumSource(
      value = CertificateIdGeneration.class,
      names = {"VALID_CERTID"},
      mode = EnumSource.Mode.EXCLUDE)
  void verifyOcspResponseCertId_whenCertificateIdIsInvalid_thenThrowsGemPkiException(
      final CertificateIdGeneration certificateIdGeneration) {
    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .certificateIdGeneration(certificateIdGeneration)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    assertThatThrownBy(
            () ->
                OcspVerification.verifyOcspResponseCertId(
                    PRODUCT_TYPE, ocspResp, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB))
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
  void verifyOcspResponseCertId_whenCertificateIdMatchesRequest_thenDoesNotThrow(
      final AlgorithmIdentifier requestAlgorithmIdentifier,
      final ResponseAlgoBehavior responseAlgoBehavior,
      final boolean responseWithNullParameterHashAlgoOfCertId) {
    final OCSPReq request =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, requestAlgorithmIdentifier);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .responseAlgoBehavior(responseAlgoBehavior)
            .withNullParameterHashAlgoOfCertId(responseWithNullParameterHashAlgoOfCertId)
            .build()
            .generate(request, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    assertDoesNotThrow(
        () ->
            OcspVerification.verifyOcspResponseCertId(
                PRODUCT_TYPE, ocspResp, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB));
  }

  @Test
  void verifyThisUpdate_whenTimestampIsAtFutureToleranceBoundary_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp =
        genOcspRespWithThisUpdate(
            referenceDate.plus(OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS, ChronoUnit.MILLIS));

    assertDoesNotThrow(
        () -> OcspVerification.verifyThisUpdate(PRODUCT_TYPE, ocspResp, referenceDate));
  }

  @Test
  void verifyThisUpdate_whenTimestampIsInPast_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp = genOcspRespWithThisUpdate(referenceDate.minusYears(1));

    assertDoesNotThrow(
        () -> OcspVerification.verifyThisUpdate(PRODUCT_TYPE, ocspResp, referenceDate));
  }

  @Test
  void verifyThisUpdate_whenTimestampExceedsFutureTolerance_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp =
        genOcspRespWithThisUpdate(
            referenceDate.plus(
                OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS,
                ChronoUnit.MILLIS));

    assertThatThrownBy(
            () -> OcspVerification.verifyThisUpdate(PRODUCT_TYPE, ocspResp, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyProducedAt_whenTimestampIsAtDefaultFutureToleranceBoundary_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp =
        genOcspRespWithProducedAt(
            referenceDate.plus(
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS, ChronoUnit.MILLIS));

    assertDoesNotThrow(
        () -> OcspVerification.verifyProducedAt(PRODUCT_TYPE, ocspResp, referenceDate));
  }

  @Test
  void verifyProducedAt_whenTimestampExceedsDefaultFutureTolerance_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp =
        genOcspRespWithProducedAt(
            referenceDate.plus(
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS
                    + TIMEOUT_DELTA_MILLISECONDS,
                ChronoUnit.MILLIS));

    assertThatThrownBy(
            () -> OcspVerification.verifyProducedAt(PRODUCT_TYPE, ocspResp, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyProducedAt_whenTimestampIsWithinCustomPastTolerance_thenDoesNotThrow() {
    final int customToleranceMilliseconds = 10000;
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp =
        genOcspRespWithProducedAt(
            referenceDate.minus(
                customToleranceMilliseconds - TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS));

    assertDoesNotThrow(
        () ->
            OcspVerification.verifyProducedAt(
                PRODUCT_TYPE,
                ocspResp,
                referenceDate,
                customToleranceMilliseconds,
                customToleranceMilliseconds));
  }

  @Test
  void verifyProducedAt_whenTimestampExceedsCustomPastTolerance_thenThrowsGemPkiException() {
    final int customToleranceMilliseconds = 10000;
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp =
        genOcspRespWithProducedAt(
            referenceDate.minus(
                customToleranceMilliseconds + TIMEOUT_DELTA_MILLISECONDS, ChronoUnit.MILLIS));

    assertThatThrownBy(
            () ->
                OcspVerification.verifyProducedAt(
                    PRODUCT_TYPE,
                    ocspResp,
                    referenceDate,
                    customToleranceMilliseconds,
                    customToleranceMilliseconds))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyNextUpdate_whenTimestampExceedsPastTolerance_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp =
        genOcspRespWithNextUpdate(
            referenceDate.minus(
                OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS + TIMEOUT_DELTA_MILLISECONDS,
                ChronoUnit.MILLIS));

    assertThatThrownBy(
            () -> OcspVerification.verifyNextUpdate(PRODUCT_TYPE, ocspResp, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyNextUpdate_whenTimestampIsWithinPastTolerance_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp =
        genOcspRespWithNextUpdate(
            referenceDate.minus(
                OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS - TIMEOUT_DELTA_MILLISECONDS,
                ChronoUnit.MILLIS));

    assertDoesNotThrow(
        () -> OcspVerification.verifyNextUpdate(PRODUCT_TYPE, ocspResp, referenceDate));
  }

  @Test
  void verifyNextUpdate_whenTimestampIsInFuture_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp = genOcspRespWithNextUpdate(referenceDate.plusYears(1));

    assertDoesNotThrow(
        () -> OcspVerification.verifyNextUpdate(PRODUCT_TYPE, ocspResp, referenceDate));
  }

  @Test
  void verifyNextUpdate_whenTimestampIsMissing_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final OCSPResp ocspResp = genOcspRespWithNextUpdate(null);

    assertDoesNotThrow(
        () -> OcspVerification.verifyNextUpdate(PRODUCT_TYPE, ocspResp, referenceDate));
  }

  @Test
  void verifyMethods_whenRequiredArgumentsAreNull_thenThrowsOnNonNullParameter() {
    final var ocspResp = genDefaultOcspResp();
    final var now = ZonedDateTime.now();

    assertNonNullParameter(() -> OcspVerification.verifyStatus(null, ocspResp, now), "productType");
    assertNonNullParameter(
        () -> OcspVerification.verifyStatus(PRODUCT_TYPE, null, now), "ocspResponse");
    assertNonNullParameter(
        () -> OcspVerification.verifyStatus(PRODUCT_TYPE, ocspResp, null), "referenceDate");
    assertNonNullParameter(() -> OcspVerification.verifyStatus(null, ocspResp), "productType");
    assertNonNullParameter(() -> OcspVerification.verifyStatus(PRODUCT_TYPE, null), "ocspResponse");
    assertNonNullParameter(
        () -> OcspVerification.verifyThisUpdate(null, ocspResp, now), "productType");
    assertNonNullParameter(
        () -> OcspVerification.verifyThisUpdate(PRODUCT_TYPE, null, now), "ocspResponse");
    assertNonNullParameter(
        () -> OcspVerification.verifyThisUpdate(PRODUCT_TYPE, ocspResp, null), "referenceDate");
    assertNonNullParameter(
        () -> OcspVerification.verifyProducedAt(null, ocspResp, now), "productType");
    assertNonNullParameter(
        () -> OcspVerification.verifyProducedAt(PRODUCT_TYPE, null, now), "ocspResponse");
    assertNonNullParameter(
        () -> OcspVerification.verifyProducedAt(PRODUCT_TYPE, ocspResp, null), "referenceDate");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyProducedAt(
                null,
                ocspResp,
                now,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "productType");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyProducedAt(
                PRODUCT_TYPE,
                null,
                now,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "ocspResponse");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyProducedAt(
                PRODUCT_TYPE,
                ocspResp,
                null,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "referenceDate");
    assertNonNullParameter(
        () -> OcspVerification.verifyNextUpdate(null, ocspResp, now), "productType");
    assertNonNullParameter(
        () -> OcspVerification.verifyNextUpdate(PRODUCT_TYPE, null, now), "ocspResponse");
    assertNonNullParameter(
        () -> OcspVerification.verifyNextUpdate(PRODUCT_TYPE, ocspResp, null), "referenceDate");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseCertId(
                null, ocspResp, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB),
        "productType");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseCertId(
                PRODUCT_TYPE, null, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB),
        "ocspResponse");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseCertId(
                PRODUCT_TYPE, ocspResp, null, VALID_ISSUER_CERT_SMCB),
        "eeCert");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseCertId(
                PRODUCT_TYPE, ocspResp, VALID_X509_EE_CERT_SMCB, null),
        "issuerCert");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponse(
                null,
                ocspResp,
                now,
                now,
                VALID_X509_EE_CERT_SMCB,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "productType");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponse(
                PRODUCT_TYPE,
                null,
                now,
                now,
                VALID_X509_EE_CERT_SMCB,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "ocspResponse");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponse(
                PRODUCT_TYPE,
                ocspResp,
                null,
                now,
                VALID_X509_EE_CERT_SMCB,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "referenceDate");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponse(
                PRODUCT_TYPE,
                ocspResp,
                now,
                null,
                VALID_X509_EE_CERT_SMCB,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "plausibilityReferenceDate");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponse(
                PRODUCT_TYPE,
                ocspResp,
                now,
                now,
                null,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "eeCert");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponse(
                PRODUCT_TYPE,
                ocspResp,
                now,
                now,
                VALID_X509_EE_CERT_SMCB,
                null,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "issuerCert");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseAfterStatus(
                null,
                ocspResp,
                now,
                VALID_X509_EE_CERT_SMCB,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "productType");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseAfterStatus(
                PRODUCT_TYPE,
                null,
                now,
                VALID_X509_EE_CERT_SMCB,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "ocspResponse");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseAfterStatus(
                PRODUCT_TYPE,
                ocspResp,
                null,
                VALID_X509_EE_CERT_SMCB,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "referenceDate");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseAfterStatus(
                PRODUCT_TYPE,
                ocspResp,
                now,
                null,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "eeCert");
    assertNonNullParameter(
        () ->
            OcspVerification.verifyOcspResponseAfterStatus(
                PRODUCT_TYPE,
                ocspResp,
                now,
                VALID_X509_EE_CERT_SMCB,
                null,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS),
        "issuerCert");
  }

  /*
  Verify bug from version 5.0.1
   */
  @Test
  void
      verifyOcspResponseAfterStatus_whenProducedAtIsBeforeThisUpdateButWithinTolerances_thenDoesNotThrow() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();
    final ZonedDateTime thisUpdate =
        referenceDate.plus(
            OCSP_TIME_TOLERANCE_THISNEXTUPDATE_MILLISECONDS - TIMEOUT_DELTA_MILLISECONDS,
            ChronoUnit.MILLIS);
    final ZonedDateTime producedAt =
        referenceDate.minus(
            OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS - TIMEOUT_DELTA_MILLISECONDS,
            ChronoUnit.MILLIS);

    final OCSPResp ocspResp = genOcspRespWithThisUpdateAndProducedAt(thisUpdate, producedAt);

    final ZonedDateTime thisUpdateFromResponse =
        ZonedDateTime.ofInstant(
            OcspUtils.getFirstSingleResp(ocspResp).getThisUpdate().toInstant(),
            referenceDate.getZone());
    final ZonedDateTime producedAtFromResponse =
        ZonedDateTime.ofInstant(
            OcspUtils.getBasicOcspResp(ocspResp).getProducedAt().toInstant(),
            referenceDate.getZone());
    assertThat(producedAtFromResponse).isBefore(thisUpdateFromResponse);

    assertDoesNotThrow(
        () ->
            OcspVerification.verifyOcspResponseAfterStatus(
                PRODUCT_TYPE,
                ocspResp,
                referenceDate,
                VALID_X509_EE_CERT_SMCB,
                VALID_ISSUER_CERT_SMCB,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS,
                OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS));
  }

  private static OCSPResp genDefaultOcspResp() {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  private static OCSPResp genOcspRespWithThisUpdate(final ZonedDateTime thisUpdate) {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .thisUpdate(thisUpdate)
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  private static OCSPResp genOcspRespWithProducedAt(final ZonedDateTime producedAt) {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .producedAt(producedAt)
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  private static OCSPResp genOcspRespWithNextUpdate(final ZonedDateTime nextUpdate) {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .nextUpdate(nextUpdate)
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  private static OCSPResp genOcspRespWithThisUpdateAndProducedAt(
      final ZonedDateTime thisUpdate, final ZonedDateTime producedAt) {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .thisUpdate(thisUpdate)
        .producedAt(producedAt)
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }
}
