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

package de.gematik.pki.gemlibpki.certificate;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.INVALID_CERT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.MISSING_CERT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.MISSING_EXT_KEY_USAGE_EE_CERT;
import static de.gematik.pki.gemlibpki.TestConstants.MISSING_POLICY_ID_CERT;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_HBA_AUT_ECC;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_ALT_CA;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_INVALID_KEY_USAGE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_ANY;
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
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

class CertificateProfileVerificationTest {

  private String productType;
  private CertificateProfileVerification certificateProfileVerification;

  @BeforeEach
  void setUp() throws GemPkiException {

    productType = "IDP";
    certificateProfileVerification = buildCertificateProfileVerifier(CERT_PROFILE_C_HCI_AUT_ECC);
  }

  private CertificateProfileVerification buildCertificateProfileVerifier(
      final CertificateProfile certificateProfile) throws GemPkiException {
    return buildCertificateProfileVerifier(
        FILE_NAME_TSL_ECC_DEFAULT, certificateProfile, VALID_X509_EE_CERT_SMCB);
  }

  private CertificateProfileVerification buildCertificateProfileVerifier(
      @NonNull final String tslFilename,
      final CertificateProfile certificateProfile,
      final X509Certificate x509EeCert)
      throws GemPkiException {

    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(
                new TslInformationProvider(TestUtils.getTslUnsigned(tslFilename)).getTspServices(),
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
        () ->
            buildCertificateProfileVerifier(
                FILE_NAME_TSL_ECC_DEFAULT, null, VALID_X509_EE_CERT_SMCB),
        "certificateProfile");
  }

  @Test
  void verifyTspProfileNull() {
    assertNonNullParameter(
        () ->
            buildCertificateProfileVerifier(
                null, CERT_PROFILE_C_HCI_AUT_ECC, VALID_X509_EE_CERT_SMCB),
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
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, missingKeyUsagex509EeCert);
    assertThatThrownBy(verifier::verifyKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyKeyUsageInvalidInCertificate() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT,
            CERT_PROFILE_C_HCI_AUT_ECC,
            VALID_X509_EE_CERT_INVALID_KEY_USAGE);
    assertThatThrownBy(verifier::verifyKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1016_WRONG_KEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyKeyUsageInvalidInCertificateButNotChecked() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_ANY, VALID_X509_EE_CERT_INVALID_KEY_USAGE);
    assertDoesNotThrow(verifier::verifyKeyUsage);
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

    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, VALID_HBA_AUT_ECC);
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

    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, VALID_HBA_AUT_ECC);
    assertThatThrownBy(verifier::verifyExtendedKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyExtendedKeyUsageMissingInCertificate() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, MISSING_EXT_KEY_USAGE_EE_CERT);
    assertThatThrownBy(verifier::verifyExtendedKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyExtendedKeyUsageMissingInCertificateAndNotExpected() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_ANY, MISSING_EXT_KEY_USAGE_EE_CERT);
    assertDoesNotThrow(verifier::verifyExtendedKeyUsage);
  }

  @Test
  void verifyExtendedKeyUsageNotChecked() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_ANY, VALID_X509_EE_CERT_SMCB);
    assertDoesNotThrow(verifier::verifyExtendedKeyUsage);
  }

  @Test
  void verifyExtendedKeyUsageInvalidInCertificate() throws GemPkiException {
    final X509Certificate invalidExtendedKeyUsageEeCert =
        TestUtils.readCert("GEM.SMCB-CA10/invalid/DrMedGunther_invalid-ext-keyusage.pem");
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, invalidExtendedKeyUsageEeCert);
    assertThatThrownBy(verifier::verifyExtendedKeyUsage)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
  }

  @Test
  void verifyExtendedKeyUsageCertificateParsingException()
      throws GemPkiException, CertificateParsingException {

    final X509Certificate cert = Mockito.spy(VALID_X509_EE_CERT_SMCB);
    Mockito.when(cert.getExtendedKeyUsage()).thenThrow(new CertificateParsingException());

    certificateProfileVerification =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, cert);

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
                    FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, eeMultipleCertTypes)
                .verifyCertificateType());
  }

  @Test
  void verifyCertificateProfileMissingPolicyId() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, MISSING_POLICY_ID_CERT);
    assertThatThrownBy(verifier::verifyCertificateType)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING.getErrorMessage(productType));
  }

  @Test
  void verifyCertificateProfileMissingCertType() throws GemPkiException {

    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, MISSING_CERT_TYPE);
    assertThatThrownBy(verifier::verifyCertificateType)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING.getErrorMessage(productType));
  }

  @Test
  void verifyCertificateProfileInvalidCertType() throws GemPkiException {
    final CertificateProfileVerification verifier =
        buildCertificateProfileVerifier(
            FILE_NAME_TSL_ECC_DEFAULT, CERT_PROFILE_C_HCI_AUT_ECC, INVALID_CERT_TYPE);
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
            tslAltCaWrongServiceExtension, CERT_PROFILE_C_HCI_AUT_ECC, VALID_X509_EE_CERT_ALT_CA);
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

  @Test
  void testGetCertificatePolicyOidsException() {

    try (final MockedConstruction<Policies> ignored =
        Mockito.mockConstructionWithAnswer(
            Policies.class,
            invocation -> {
              throw new IOException();
            })) {

      assertThatThrownBy(() -> certificateProfileVerification.verifyCertificateType())
          .isInstanceOf(GemPkiException.class)
          .hasMessage(ErrorCode.TE_1019_CERT_READ_ERROR.getErrorMessage(productType));
    }
  }
}
