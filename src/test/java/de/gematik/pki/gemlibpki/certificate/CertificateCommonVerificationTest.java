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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_ALT_CA;
import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.utils.CertificateProvider;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Dieser Test arbeitet ausschließlich mit einem Zertifikatsprofil (SMCB). Andere Profile zu testen
 * wäre vermutlich akademisch.
 */
class CertificateCommonVerificationTest {

  private static ZonedDateTime DATETIME_TO_CHECK;
  private CertificateCommonVerification certificateCommonVerification;
  private X509Certificate validX509EeCertAltCa;
  private X509Certificate validX509IssuerCert;

  @BeforeEach
  void setUp() throws GemPkiException {
    final X509Certificate VALID_X509_EE_CERT =
        CertificateProvider.getX509Certificate(
            ResourceReader.getFilePathFromResources(
                "certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem"));
    validX509EeCertAltCa =
        CertificateProvider.getX509Certificate(
            ResourceReader.getFilePathFromResources(
                "certificates/GEM.SMCB-CA33/DrMedGuntherKZV.pem"));
    validX509IssuerCert =
        CertificateProvider.getX509Certificate(
            ResourceReader.getFilePathFromResources(
                "certificates/GEM.SMCB-CA10/GEM.SMCB-CA10_TEST-ONLY.pem"));
    DATETIME_TO_CHECK = ZonedDateTime.parse("2020-11-20T15:00:00Z");
    certificateCommonVerification =
        buildCertificateCommonVerifier(FILE_NAME_TSL_ECC_DEFAULT, VALID_X509_EE_CERT);
  }

  private CertificateCommonVerification buildCertificateCommonVerifier(
      @NonNull final String tslFilename, final X509Certificate x509EeCert) throws GemPkiException {

    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(
                new TslInformationProvider(TestUtils.getTsl(tslFilename)).getTspServices(),
                PRODUCT_TYPE)
            .getIssuerTspServiceSubset(x509EeCert);

    return CertificateCommonVerification.builder()
        .productType(PRODUCT_TYPE)
        .x509EeCert(x509EeCert)
        .tspServiceSubset(tspServiceSubset)
        .build();
  }

  @Test
  void verifyCertificateEndEntityNull() {
    assertThatThrownBy(() -> buildCertificateCommonVerifier(FILE_NAME_TSL_ECC_DEFAULT, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("x509EeCert is marked non-null but is null");
  }

  @Test
  void verifySignatureIssuerNull() {
    assertThatThrownBy(() -> certificateCommonVerification.verifySignature(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("x509IssuerCert is marked non-null but is null");
  }

  @Test
  void verifySignatureValid() {
    assertDoesNotThrow(() -> certificateCommonVerification.verifySignature(validX509IssuerCert));
  }

  @Test
  void verifySignatureNotValid() throws GemPkiException {
    final X509Certificate invalidX509EeCert =
        CertificateProvider.getX509Certificate(
            Path.of(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-signature.pem"));
    final CertificateCommonVerification verifier =
        buildCertificateCommonVerifier(FILE_NAME_TSL_ECC_ALT_CA, invalidX509EeCert);

    assertThatThrownBy(() -> verifier.verifySignature(validX509IssuerCert))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1024_CERTIFICATE_NOT_VALID_MATH.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyValidityReferenceDateNull() {
    assertThatThrownBy(() -> certificateCommonVerification.verifyValidity(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("referenceDate is marked non-null but is null");
  }

  @Test
  void verifyValidityCertificateExpired() throws GemPkiException {
    final X509Certificate expiredEeCert =
        CertificateProvider.getX509Certificate(
            Path.of(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_expired.pem"));
    final CertificateCommonVerification verifier =
        buildCertificateCommonVerifier(FILE_NAME_TSL_ECC_DEFAULT, expiredEeCert);
    assertThatThrownBy(() -> verifier.verifyValidity(DATETIME_TO_CHECK))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyValidityCertificateNotYetValid() throws GemPkiException {
    final X509Certificate notYetValidEeCert =
        CertificateProvider.getX509Certificate(
            Path.of(
                "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_not-yet-valid.pem"));
    final CertificateCommonVerification verifier =
        buildCertificateCommonVerifier(FILE_NAME_TSL_ECC_DEFAULT, notYetValidEeCert);
    assertThatThrownBy(() -> verifier.verifyValidity(DATETIME_TO_CHECK))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1021_CERTIFICATE_NOT_VALID_TIME.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyValidityCertificateValid() {
    assertDoesNotThrow(() -> certificateCommonVerification.verifyValidity(DATETIME_TO_CHECK));
  }

  @Test
  void verifyIssuerServiceStatusInaccord() {
    assertDoesNotThrow(
        () ->
            buildCertificateCommonVerifier(FILE_NAME_TSL_ECC_ALT_CA, validX509EeCertAltCa)
                .verifyIssuerServiceStatus());
  }

  /**
   * Timestamp "notBefore" of VALID_X509_EE_CERT_ALT_CA is before StatusStartingTime of TSPService
   * (issuer of VALID_X509_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
   */
  @Test
  void verifyIssuerServiceStatusRevokedLater() {
    final String tslAltCaRevokedLater = "tsls/ecc/valid/TSL_altCA_revokedLater.xml";
    assertDoesNotThrow(
        () ->
            buildCertificateCommonVerifier(tslAltCaRevokedLater, validX509EeCertAltCa)
                .verifyIssuerServiceStatus());
  }

  /**
   * Timestamp "notBefore" of VALID_X509_EE_CERT_ALT_CA is after StatusStartingTime of TSPService
   * (issuer of VALID_X509_EE_CERT_ALT_CA) in TSL FILE_NAME_TSL_ALT_CA_REVOKED
   */
  @Test
  void verifyIssuerServiceStatusRevoked() throws GemPkiException {
    final CertificateCommonVerification verifier =
        buildCertificateCommonVerifier(
            "tsls/ecc/valid/TSL_altCA_revoked.xml", validX509EeCertAltCa);
    assertThatThrownBy(verifier::verifyIssuerServiceStatus)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1036_CA_CERTIFICATE_REVOKED_IN_TSL.getErrorMessage(PRODUCT_TYPE));
  }
}
