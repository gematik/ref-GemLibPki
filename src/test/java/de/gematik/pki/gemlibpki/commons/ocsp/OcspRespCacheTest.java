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

import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_SMCB_CA41_RSA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB_CA41_RSA;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Optional;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OcspRespCacheTest {

  static OCSPReq ocspReq;

  @BeforeAll
  static void setup() {
    ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  private static OCSPResp generateOcspResp(
      final OCSPReq _ocspReq,
      final X509Certificate _eeCert,
      final X509Certificate _issuerCert,
      final CertificateStatus _certStatus) {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .build()
        .generate(_ocspReq, _eeCert, _issuerCert, _certStatus);
  }

  @Test
  void getOcspGracePeriodSeconds_whenCacheIsCreated_thenReturnsConfiguredGracePeriod() {
    final int OCSP_GRACE_PERIOD = 10;
    final OcspRespCache ocspRespCache = new OcspRespCache(OCSP_GRACE_PERIOD);
    assertThat(ocspRespCache.getOcspGracePeriodSeconds()).isEqualTo(OCSP_GRACE_PERIOD);
  }

  @Test
  void setOcspGracePeriodSeconds_whenCalled_thenUpdatesGracePeriod() {
    final int OCSP_GRACE_PERIOD = 10;
    final OcspRespCache ocspRespCache = new OcspRespCache(OCSP_GRACE_PERIOD);
    ocspRespCache.setOcspGracePeriodSeconds(OCSP_GRACE_PERIOD + 5);
    assertThat(ocspRespCache.getOcspGracePeriodSeconds()).isEqualTo(OCSP_GRACE_PERIOD + 5);
  }

  @Test
  void saveResponse_whenResponseIsSaved_thenSizeIncreases() {
    final OcspRespCache ocspRespCache = new OcspRespCache(30);
    assertThat(ocspRespCache.getSize()).isZero();
    final OCSPResp ocspResp = getOcspResp();
    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResp);
    assertThat(ocspRespCache.getSize()).isEqualTo(1);
  }

  @Test
  void getResponse_whenResponseWasSaved_thenReturnsCachedResponse() {
    final OcspRespCache ocspRespCache = new OcspRespCache(30);

    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber())).isEmpty();
    final OCSPResp ocspResp = getOcspResp();
    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResp);
    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber())).isPresent();
  }

  private static OCSPResp getOcspResp() {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEccNonQes())
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  private void saveAndGetResponseWithGracePeriod(final CertificateStatus certificateStatus) {

    final int gracePeriodSeconds = 2;
    final OcspRespCache ocspRespCache = new OcspRespCache(gracePeriodSeconds);

    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber())).isEmpty();

    final OCSPReq ocspReq1 = ocspReq;

    final OCSPReq ocspReq2 =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB_CA41_RSA, VALID_ISSUER_CERT_SMCB_CA41_RSA);

    final OCSPResp ocspResp1 =
        generateOcspResp(
            ocspReq1, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, certificateStatus);
    final OCSPResp ocspResp2 =
        generateOcspResp(
            ocspReq2,
            VALID_X509_EE_CERT_SMCB_CA41_RSA,
            VALID_ISSUER_CERT_SMCB_CA41_RSA,
            certificateStatus);

    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResp1);
    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB_CA41_RSA.getSerialNumber(), ocspResp2);

    assertThat(ocspRespCache.getSize()).isEqualTo(2);

    Optional<OCSPResp> ocspRespX =
        ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB_CA41_RSA.getSerialNumber());
    assertThat(ocspRespX).isPresent();
    assertThat(ocspRespCache.getSize()).isEqualTo(2);

    TestUtils.waitSeconds(gracePeriodSeconds + 1);

    ocspRespX = ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB_CA41_RSA.getSerialNumber());
    assertThat(ocspRespX).isEmpty();
    assertThat(ocspRespCache.getSize()).isZero();
  }

  @Test
  void getResponse_whenGracePeriodExpiresForGoodStatus_thenRemovesCachedResponses() {
    saveAndGetResponseWithGracePeriod(CertificateStatus.GOOD);
  }

  @Test
  void getResponse_whenGracePeriodExpiresForUnknownStatus_thenRemovesCachedResponses() {
    saveAndGetResponseWithGracePeriod(new UnknownStatus());
  }

  @Test
  void getResponse_whenGracePeriodExpiresForRevokedStatus_thenRemovesCachedResponses() {

    final ZonedDateTime revokedDate = ZonedDateTime.now(ZoneOffset.UTC);
    final int revokedReason = CRLReason.aACompromise;
    final RevokedStatus revokedStatus =
        new RevokedStatus(Date.from(revokedDate.toInstant()), revokedReason);

    saveAndGetResponseWithGracePeriod(revokedStatus);
  }

  @Test
  void getResponse_whenRevokedResponseIsFreshAndSuccessful_thenKeepsResponseInCache() {
    final ZonedDateTime thisUpdate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime producedAt = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime nextUpdate = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(10);
    final ZonedDateTime revocationTime = ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(10);

    final OCSPResp ocspResp =
        TestUtils.generateOcspResponseWithTimeStamps(
            VALID_X509_EE_CERT_SMCB,
            VALID_ISSUER_CERT_SMCB,
            OcspTestConstants.getOcspSignerEccNonQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            new RevokedStatus(Date.from(revocationTime.toInstant()), CRLReason.privilegeWithdrawn));

    final int OCSP_GRACE_PERIOD = 30;
    final OcspRespCache ocspRespCache = new OcspRespCache(OCSP_GRACE_PERIOD);
    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResp);

    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber())).isPresent();
  }

  @Test
  void ocspRespCacheMethods_whenRequiredParameterIsNull_thenThrowsException() {
    final OcspRespCache ocspRespCache = new OcspRespCache(30);
    assertNonNullParameter(() -> ocspRespCache.getResponse(null), "certSerialNr");

    final OCSPResp ocspResp = getOcspResp();
    assertNonNullParameter(() -> ocspRespCache.saveResponse(null, ocspResp), "certSerialNr");
    final BigInteger certSerialNr = BigInteger.valueOf(1);
    assertNonNullParameter(() -> ocspRespCache.saveResponse(certSerialNr, null), "ocspResp");
  }

  @Test
  void getResponse_whenCachedResponseIsExpired_thenDeletesResponseOnAccess() {
    final OcspRespCache ocspRespCache = new OcspRespCache(30);
    final ZonedDateTime thisUpdate = ZonedDateTime.now(ZoneOffset.UTC).minusDays(10);
    final ZonedDateTime producedAt = thisUpdate.plusSeconds(1);
    final ZonedDateTime nextUpdate = producedAt.plusDays(1);
    final OCSPResp ocspResp =
        TestUtils.generateOcspResponseWithTimeStamps(
            VALID_X509_EE_CERT_SMCB,
            VALID_ISSUER_CERT_SMCB,
            OcspTestConstants.getOcspSignerEccNonQes(),
            null,
            thisUpdate,
            producedAt,
            nextUpdate,
            CertificateStatus.GOOD);

    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResp);
    // this response is cached but will be deleted on next cache access
    assertThat(ocspRespCache.getSize()).isEqualTo(1);
    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber())).isEmpty();
  }
}
