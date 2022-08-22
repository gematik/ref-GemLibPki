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

import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB_RSA;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.utils.CertificateProvider;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Optional;
import org.apache.commons.lang3.function.TriFunction;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class OcspRespCacheTest {

  static X509Certificate VALID_X509_EE_CERT;
  static X509Certificate VALID_X509_ISSUER_CERT;
  static OCSPReq ocspReq;

  @BeforeAll
  static void setup() {
    VALID_X509_EE_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
    // certificate is not issued by VALID_X509_ISSUER_CERT - this will fail when certHash check is
    // implemented
    VALID_X509_ISSUER_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.RCA1_TEST-ONLY.pem");
    ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);
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
    ocspRespCache.saveResponse(VALID_X509_EE_CERT.getSerialNumber(), ocspResp);
    assertThat(ocspRespCache.getSize()).isEqualTo(1);
  }

  @Test
  void saveAndGetResponse() {
    final OcspRespCache ocspRespCache = new OcspRespCache(30);

    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT.getSerialNumber())).isEmpty();
    final OCSPResp ocspResp = getOcspResp();
    ocspRespCache.saveResponse(VALID_X509_EE_CERT.getSerialNumber(), ocspResp);
    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT.getSerialNumber())).isPresent();
  }

  private static OCSPResp getOcspResp() {
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerRsa())
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT);
  }

  private void saveAndGetResponseWithGracePeriod(final CertificateStatus certificateStatus) {

    final TriFunction<OCSPReq, X509Certificate, CertificateStatus, OCSPResp> ocspRespGen =
        (_ocspReq, _eeCert, _certStatus) ->
            OcspResponseGenerator.builder()
                .signer(OcspTestConstants.getOcspSignerRsa())
                .build()
                .generate(_ocspReq, _eeCert, _certStatus);

    final int gracePeriodSeconds = 2;
    final OcspRespCache ocspRespCache = new OcspRespCache(gracePeriodSeconds);

    assertThat(ocspRespCache.getResponse(VALID_X509_EE_CERT.getSerialNumber())).isEmpty();

    final X509Certificate eeCert1 = VALID_X509_EE_CERT;
    final OCSPReq ocspReq1 = ocspReq;

    final X509Certificate eeCert2 = TestUtils.readCert("GEM.SMCB-CA24-RSA/AschoffscheApotheke.pem");
    final OCSPReq ocspReq2 =
        OcspRequestGenerator.generateSingleOcspRequest(eeCert2, VALID_ISSUER_CERT_SMCB_RSA);

    final OCSPResp ocspResp1 = ocspRespGen.apply(ocspReq1, eeCert1, certificateStatus);
    final OCSPResp ocspResp2 = ocspRespGen.apply(ocspReq2, eeCert2, certificateStatus);

    ocspRespCache.saveResponse(eeCert1.getSerialNumber(), ocspResp1);
    ocspRespCache.saveResponse(eeCert2.getSerialNumber(), ocspResp2);

    assertThat(ocspRespCache.getSize()).isEqualTo(2);

    Optional<OCSPResp> ocspRespX = ocspRespCache.getResponse(eeCert2.getSerialNumber());
    assertThat(ocspRespX).isPresent();
    assertThat(ocspRespCache.getSize()).isEqualTo(2);

    TestUtils.waitSeconds(gracePeriodSeconds + 1);

    ocspRespX = ocspRespCache.getResponse(eeCert2.getSerialNumber());
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
    assertThatThrownBy(() -> ocspRespCache.getResponse(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("x509EeCertSerialNumber is marked non-null but is null");

    final OCSPResp ocspResp = getOcspResp();
    assertThatThrownBy(() -> ocspRespCache.saveResponse(null, ocspResp))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("x509EeCertSerialNumber is marked non-null but is null");
    final BigInteger SERIAL_NUMBER = BigInteger.valueOf(1);
    assertThatThrownBy(() -> ocspRespCache.saveResponse(SERIAL_NUMBER, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("ocspResp is marked non-null but is null");
  }
}
