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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_RSA;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_HP_AUT_ECC;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class CertificateProfileVerificationTest {

  private final CertificateProfile certificateProfile = CERT_PROFILE_C_HCI_AUT_ECC;
  private String productType;
  private CertificateProfileVerification certificateProfileVerification;
  private X509Certificate validX509EeCert;
  private X509Certificate validX509EeCertAltCa;

  @BeforeEach
  void setUp() throws GemPkiException {
    validX509EeCert = TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther.pem");
    validX509EeCertAltCa = TestUtils.readCert("GEM.SMCB-CA33/DrMedGuntherKZV.pem");
    productType = "IDP";
    certificateProfileVerification = buildCertificateProfileVerifier(certificateProfile);
  }

  private CertificateProfileVerification buildCertificateProfileVerifier(
      final CertificateProfile certificateProfile) throws GemPkiException {
    return buildCertificateProfileVerifier(
        FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, validX509EeCert);
  }

  private CertificateProfileVerification buildCertificateProfileVerifier(
      @NonNull final String tslFilename,
      final CertificateProfile certificateProfile,
      final X509Certificate x509EeCert)
      throws GemPkiException {

    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(
                new TslInformationProvider(TestUtils.getTsl(tslFilename)).getTspServices(),
                productType)
            .getIssuerTspServiceSubset(x509EeCert);

    return CertificateProfileVerification.builder()
        .productType(productType)
        .x509EeCert(x509EeCert)
        .certificateProfile(certificateProfile)
        .tspServiceSubset(tspServiceSubset)
        .build();
  }

  @Test
  void verifyCertificateProfileNull() {
    assertNonNullParameter(
        () -> buildCertificateProfileVerifier(FILE_NAME_TSL_ECC_DEFAULT, null, validX509EeCert),
        "certificateProfile");
  }

  @Test
  void verifyTspProfileNull() {
    assertNonNullParameter(
        () -> buildCertificateProfileVerifier(null, certificateProfile, validX509EeCert),
        "tslFilename");
  }

  @Test
  void verifyKeyUsageValid() {
    assertDoesNotThrow(() -> certificateProfileVerification.verifyKeyUsage());
  }

  @Test
  void verifyKeyUsageMissingInCertificate() throws GemPkiException {
    final X509Certificate missingKeyUsagex509EeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_missing-keyusage.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, missingKeyUsagex509EeCert);
    assertThatThrownBy(verifier::verifyKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyKeyUsageInvalidInCertificate() throws GemPkiException {
    final X509Certificate invalidKeyUsagex509EeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-keyusage.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, invalidKeyUsagex509EeCert);
    assertThatThrownBy(verifier::verifyKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyNotAllKeyUsagesPresentInCert() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(CERT_PROFILE_C_HCI_AUT_RSA);
    assertThatThrownBy(verifier::verifyKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyToManyKeyUsagesPresentInCert() throws GemPkiException {
    final X509Certificate validHbaAutEcc = TestUtils.readCert("GEM.HBA-CA13/GüntherOtís.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, validHbaAutEcc);
    assertThatThrownBy(verifier::verifyKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyExtendedKeyUsageValid() {
    assertDoesNotThrow(() -> certificateProfileVerification.verifyExtendedKeyUsage());
  }

  @Test
  void verifyNotAllExtendedKeyUsagesPresentInCert() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(CERT_PROFILE_C_HP_AUT_ECC);
    assertThatThrownBy(verifier::verifyExtendedKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyToManyExtendedKeyUsagesPresentInCert() throws GemPkiException {
    final X509Certificate validHbaAutEcc = TestUtils.readCert("GEM.HBA-CA13/GüntherOtís.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, validHbaAutEcc);
    assertThatThrownBy(verifier::verifyExtendedKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyExtendedKeyUsageMissingInCertificate() throws GemPkiException {
    final X509Certificate missingExtKeyUsagex509EeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_missing-extKeyUsage.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, missingExtKeyUsagex509EeCert);
    assertThatThrownBy(verifier::verifyExtendedKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyExtendedKeyUsageInvalidInCertificate() throws GemPkiException {
    final X509Certificate invalidExtendedKeyUsageEeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-ext-keyusage.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, invalidExtendedKeyUsageEeCert);
    assertThatThrownBy(verifier::verifyExtendedKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyExtendedKeyUsageCertificateParsingException()
      throws GemPkiException, CertificateParsingException {

    final X509Certificate cert = Mockito.spy(validX509EeCert);
    Mockito.when(cert.getExtendedKeyUsage()).thenThrow(new CertificateParsingException());

    certificateProfileVerification =
        buildCertificateProfileVerifier(FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, cert);

    assertThatThrownBy(certificateProfileVerification::verifyExtendedKeyUsage)
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(
            "Fehler beim Lesen der ExtendedKeyUsages des Zertifikats: CN=Zahnarztpraxis Dr."
                + " med.Gunther KZV"
                + " TEST-ONLY,2.5.4.5=#131731372e3830323736383833313139313130303033333237,O=2-2.30.1.16.TestOnly"
                + " NOT-VALID,C=DE");
  }

  @Test
  void multipleCertificateProfilesMultipleCertTypesInEe() {
    final X509Certificate eeMultipleCertTypes =
        TestUtils.readCert("GEM.SMCB-CA9/Aschoffsche_Apotheke_twoCertTypes.pem");
    assertDoesNotThrow(
        () ->
            buildCertificateProfileVerifier(
                    FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, eeMultipleCertTypes)
                .verifyCertificateType());
  }

  @Test
  void verifyCertificateProfileMissingPolicyId() throws GemPkiException {
    final X509Certificate missingPolicyId =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_missing-policyId.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, missingPolicyId);
    assertThatThrownBy(verifier::verifyCertificateType)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING.getErrorMessage(productType));
  }

  @Test
  void verifyCertificateProfileMissingCertType() throws GemPkiException {
    final X509Certificate missingCertType =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_missing-certificate-type.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, missingCertType);
    assertThatThrownBy(verifier::verifyCertificateType)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING.getErrorMessage(productType));
  }

  @Test
  void verifyCertificateProfileInvalidCertType() throws GemPkiException {
    final X509Certificate invalidCertType =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-certificate-type.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, invalidCertType);
    assertThatThrownBy(verifier::verifyCertificateType)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1018_CERT_TYPE_MISMATCH.getErrorMessage(productType));
  }

  @Test
  void verifyCertificateProfileWrongServiceInfoExtInTsl() throws GemPkiException {
    final String tslAltCaWrongServiceExtension =
        "tsls/ecc/defect/TSL_defect_altCA_wrong-srvInfoExt.xml";
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            tslAltCaWrongServiceExtension, certificateProfile, validX509EeCertAltCa);
    assertThatThrownBy(verifier::verifyCertificateType)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1061_CERT_TYPE_CA_NOT_AUTHORIZED.getErrorMessage(productType));
  }

  @Test
  void verifyCriticalExtensions() throws GemPkiException {
    final String certFilename = "GEM.SMCB-CA10/invalid/DrMedGunther_invalid-extension-crit.pem";
    final X509Certificate certInvalidCriticalExtension = TestUtils.readCert(certFilename);

    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, certInvalidCriticalExtension);

    assertThatThrownBy(verifier::verifyCriticalExtensions)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.CUSTOM_CERTIFICATE_EXCEPTION.getErrorMessage(productType));
  }
}
