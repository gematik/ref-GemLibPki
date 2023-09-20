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

import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB_CA24_RSA;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB_CA24_RSA;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.utils.TestUtils;
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
        .signer(OcspTestConstants.getOcspSignerEcc())
        .build()
        .generate(_ocspReq, _eeCert, _issuerCert, _certStatus);
  }

  @Test
  void setAndGetOcspGracePeriodSeconds() {
    final int OCSP_GRACE_PERIOD = 10;
    final OcspRespCache ocspRespCache = new OcspRespCache(OCSP_GRACE_PERIOD);
    assertThat(ocspRespCache.getOcspGracePeriodSeconds()).isEqualTo(OCSP_GRACE_PERIOD);
  }

  @Test
  void setAndGetOcspGracePeriodSecondsSet() {
    final int OCSP_GRACE_PERIOD = 10;
    final OcspRespCache ocspRespCache = new OcspRespCache(OCSP_GRACE_PERIOD);
    ocspRespCache.setOcspGracePeriodSeconds(OCSP_GRACE_PERIOD + 5);
    assertThat(ocspRespCache.getOcspGracePeriodSeconds()).isEqualTo(OCSP_GRACE_PERIOD + 5);
  }

  @Test
  void saveCheckSize() {
    final OcspRespCache ocspRespCache = new OcspRespCache(30);
    assertThat(ocspRespCache.getSize()).isZero();
    final OCSPResp ocspResp = getOcspResp();
    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResp);
    assertThat(ocspRespCache.getSize()).isEqualTo(1);
  }

  @Test
  void saveAndGetResponse() {
    final OcspRespCache ocspRespCache = new OcspRespCache(30);

    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber())).isEmpty();
    final OCSPResp ocspResp = getOcspResp();
    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResp);
    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber())).isPresent();
  }

  private static OCSPResp getOcspResp() {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEcc())
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
            VALID_X509_EE_CERT_SMCB_CA24_RSA, VALID_ISSUER_CERT_SMCB_CA24_RSA);

    final OCSPResp ocspResp1 =
        generateOcspResp(
            ocspReq1, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB, certificateStatus);
    final OCSPResp ocspResp2 =
        generateOcspResp(
            ocspReq2,
            VALID_X509_EE_CERT_SMCB_CA24_RSA,
            VALID_ISSUER_CERT_SMCB_CA24_RSA,
            certificateStatus);

    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB.getSerialNumber(), ocspResp1);
    ocspRespCache.saveResponse(VALID_X509_EE_CERT_SMCB_CA24_RSA.getSerialNumber(), ocspResp2);

    assertThat(ocspRespCache.getSize()).isEqualTo(2);

    Optional<OCSPResp> ocspRespX =
        ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB_CA24_RSA.getSerialNumber());
    assertThat(ocspRespX).isPresent();
    assertThat(ocspRespCache.getSize()).isEqualTo(2);

    TestUtils.waitSeconds(gracePeriodSeconds + 1);

    ocspRespX = ocspRespCache.getResponse(VALID_X509_EE_CERT_SMCB_CA24_RSA.getSerialNumber());
    assertThat(ocspRespX).isEmpty();
    assertThat(ocspRespCache.getSize()).isZero();
  }

  @Test
  void saveAndGetResponseWithGracePeriodCertificateStatusGood() {
    saveAndGetResponseWithGracePeriod(CertificateStatus.GOOD);
  }

  @Test
  void saveAndGetResponseWithGracePeriodCertificateStatusUnknown() {
    saveAndGetResponseWithGracePeriod(new UnknownStatus());
  }

  @Test
  void saveAndGetResponseWithGracePeriodCertificateStatusRevoked() {

    final ZonedDateTime revokedDate = ZonedDateTime.now(ZoneOffset.UTC);
    final int revokedReason = CRLReason.aACompromise;
    final RevokedStatus revokedStatus =
        new RevokedStatus(Date.from(revokedDate.toInstant()), revokedReason);

    saveAndGetResponseWithGracePeriod(revokedStatus);
  }

  @Test
  void nonNull() {
    final OcspRespCache ocspRespCache = new OcspRespCache(30);
    assertNonNullParameter(() -> ocspRespCache.getResponse(null), "certSerialNr");

    final OCSPResp ocspResp = getOcspResp();
    assertNonNullParameter(() -> ocspRespCache.saveResponse(null, ocspResp), "certSerialNr");
    final BigInteger certSerialNr = BigInteger.valueOf(1);
    assertNonNullParameter(() -> ocspRespCache.saveResponse(certSerialNr, null), "ocspResp");
  }
}
