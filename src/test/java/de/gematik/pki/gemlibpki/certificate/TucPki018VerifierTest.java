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

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.utils.TestUtils.configureOcspResponderMockForOcspRequest;
import static de.gematik.pki.gemlibpki.utils.TestUtils.overwriteSspUrls;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.common.OcspResponderMock;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.utils.CertificateProvider;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import de.gematik.pki.gemlibpki.utils.VariableSource;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

class TucPki018VerifierTest {

  private static TucPki018Verifier tucPki018Verifier;
  private static X509Certificate VALID_X509_EE_CERT;
  private static final CertificateProfile certificateProfile = CertificateProfile.C_HCI_AUT_ECC;
  private static final List<CertificateProfile> certificateProfiles = List.of(certificateProfile);
  private static final OcspRespCache ocspRespCache = new OcspRespCache(30);
  private static OcspResponderMock ocspResponderMock;

  @BeforeAll
  public static void start() throws Exception {
    ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    VALID_X509_EE_CERT =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/valid/DrMedGunther.pem");
    tucPki018Verifier = buildTucPki18Verifier(certificateProfiles);
  }

  private static TucPki018Verifier buildTucPki18Verifier(
      final List<CertificateProfile> certificateProfiles) {

    final List<TspService> tspServiceList =
        new TslInformationProvider(
                TslReader.getTsl(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT))
                    .orElseThrow())
            .getTspServices();

    overwriteSspUrls(tspServiceList, ocspResponderMock.getSspUrl());

    return TucPki018Verifier.builder()
        .productType(PRODUCT_TYPE)
        .tspServiceList(tspServiceList)
        .certificateProfiles(certificateProfiles)
        .ocspRespCache(ocspRespCache)
        .build();
  }

  @Test
  void verifyPerformTucPki18ChecksValid() {
    configureOcspResponderMockForOcspRequest(VALID_X509_EE_CERT, ocspResponderMock);
    assertDoesNotThrow(() -> tucPki018Verifier.performTucPki18Checks(VALID_X509_EE_CERT));
  }

  @Test
  void verifyPerformTucPki18ChecksWithoutOcsp() {
    final List<TspService> tspServiceList =
        new TslInformationProvider(
                TslReader.getTsl(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT))
                    .orElseThrow())
            .getTspServices();
    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspRespCache(ocspRespCache)
            .withOcspCheck(false)
            .build();
    assertDoesNotThrow(() -> verifier.performTucPki18Checks(VALID_X509_EE_CERT));
  }

  @Test
  void verifyEgkAutEccCertValid() {
    final X509Certificate eeCert =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.EGK-CA10/JunaFuchs.pem");
    configureOcspResponderMockForOcspRequest(eeCert, ocspResponderMock);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CertificateProfile.C_CH_AUT_ECC))
                .performTucPki18Checks(eeCert));
  }

  @Test
  void verifyHbaAutEccCertValid() {
    final X509Certificate eeCert =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.HBA-CA13/GüntherOtís.pem");
    configureOcspResponderMockForOcspRequest(eeCert, ocspResponderMock);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CertificateProfile.C_HP_AUT_ECC))
                .performTucPki18Checks(eeCert));
  }

  @Test
  void verifySmcbAutRsaCertValid() {
    final X509Certificate eeCert =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA24-RSA/AschoffscheApotheke.pem");
    configureOcspResponderMockForOcspRequest(eeCert, ocspResponderMock);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CertificateProfile.C_HCI_AUT_RSA))
                .performTucPki18Checks(eeCert));
  }

  @Test
  void verifySigDCertValid() {
    final X509Certificate eeCert =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.KOMP-CA10/c.fd.sig_keyUsage_digiSig.pem");
    configureOcspResponderMockForOcspRequest(eeCert, ocspResponderMock);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CertificateProfile.C_FD_SIG))
                .performTucPki18Checks(eeCert));
  }

  @Test
  void verifySmcbOsigRsaCertValid() {
    final X509Certificate eeCert =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA24-RSA/c-hci-osig_apo.valid.crt");
    configureOcspResponderMockForOcspRequest(eeCert, ocspResponderMock);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CertificateProfile.C_HCI_OSIG))
                .performTucPki18Checks(eeCert));
  }

  @Test
  void verifyFdOsigRsaCertValid() {
    final X509Certificate eeCert =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.KOMP-CA50/erzpecc.pem");
    configureOcspResponderMockForOcspRequest(eeCert, ocspResponderMock);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CertificateProfile.C_FD_OSIG))
                .performTucPki18Checks(eeCert));
  }

  @Test
  void verifyFdOsigEccCertValid() {
    final X509Certificate eeCert =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.KOMP-CA54/erzprsa.pem");
    configureOcspResponderMockForOcspRequest(eeCert, ocspResponderMock);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CertificateProfile.C_FD_OSIG))
                .performTucPki18Checks(eeCert));
  }

  @Test
  void verifyProfessionOidsValid() throws GemPkiException {
    final X509Certificate eeCert =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA24-RSA/c-hci-osig_apo.valid.crt");
    configureOcspResponderMockForOcspRequest(eeCert, ocspResponderMock);
    assertThat(
            buildTucPki18Verifier(List.of(CertificateProfile.C_HCI_OSIG))
                .performTucPki18Checks(eeCert)
                .getProfessionOids())
        .contains(Role.OID_OEFFENTLICHE_APOTHEKE.getProfessionOid());
  }

  @Test
  void verifyNotEveryKeyUsagePresent() {
    final X509Certificate ASCHOFFSCHE_APOTHEKE_PEM =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA24-RSA/AschoffscheApotheke.pem");
    configureOcspResponderMockForOcspRequest(ASCHOFFSCHE_APOTHEKE_PEM, ocspResponderMock);
    assertThatThrownBy(() -> tucPki018Verifier.performTucPki18Checks(ASCHOFFSCHE_APOTHEKE_PEM))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.SE_1016.name());
  }

  @Test
  void multipleCertificateProfiles_shouldSelectCorrectOne() {
    configureOcspResponderMockForOcspRequest(VALID_X509_EE_CERT, ocspResponderMock);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(
                    List.of(
                        CertificateProfile.C_TSL_SIG_ECC,
                        CertificateProfile.C_HCI_AUT_RSA,
                        CertificateProfile.C_HCI_AUT_ECC))
                .performTucPki18Checks(VALID_X509_EE_CERT));
  }

  @Test
  void multipleCertificateProfiles_shouldThrowKeyUsageError() {
    final X509Certificate eeWrongKeyUsage =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-keyusage.pem");
    configureOcspResponderMockForOcspRequest(eeWrongKeyUsage, ocspResponderMock);
    final TucPki018Verifier verifier =
        buildTucPki18Verifier(
            List.of(CertificateProfile.C_HCI_AUT_ECC, CertificateProfile.C_HP_AUT_ECC));
    assertThatThrownBy(() -> verifier.performTucPki18Checks(eeWrongKeyUsage))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.SE_1016.name());
  }

  @Test
  void multipleCertificateProfiles_shouldThrowCertTypeError() {
    final X509Certificate eeWrongKeyUsage =
        CertificateProvider.getX509Certificate(
            "src/test/resources/certificates/GEM.SMCB-CA10/invalid/DrMedGunther_invalid-certificate-type.pem");
    configureOcspResponderMockForOcspRequest(eeWrongKeyUsage, ocspResponderMock);
    final TucPki018Verifier verifier =
        buildTucPki18Verifier(
            List.of(CertificateProfile.C_HCI_AUT_ECC, CertificateProfile.C_HP_AUT_ECC));
    assertThatThrownBy(() -> verifier.performTucPki18Checks(eeWrongKeyUsage))
        .isInstanceOf(GemPkiException.class)
        .hasMessageContaining(ErrorCode.SE_1018.name());
  }

  @Test
  void verifyCertNull() {
    assertThatThrownBy(() -> tucPki018Verifier.performTucPki18Checks(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("x509EeCert");
  }

  @Test
  void verifyCertProfilesNull() {
    assertThatThrownBy(() -> buildTucPki18Verifier(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("certificateProfiles");
  }

  @Test
  void nonNullTests() {
    assertThatThrownBy(() -> tucPki018Verifier.tucPki018ProfileChecks(null, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> tucPki018Verifier.tucPki018ChecksForProfile(null, null, null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> tucPki018Verifier.commonChecks(null, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void verifyCertProfilesEmpty() {
    configureOcspResponderMockForOcspRequest(VALID_X509_EE_CERT, ocspResponderMock);
    final TucPki018Verifier verifier = buildTucPki18Verifier(List.of());
    assertThatThrownBy(() -> verifier.performTucPki18Checks(VALID_X509_EE_CERT))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Liste der konfigurierten Zertifikatsprofile ist leer.");
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = "valid")
  void verifyPerformTucPki18ChecksValid(final X509Certificate cert) {
    configureOcspResponderMockForOcspRequest(cert, ocspResponderMock);
    assertDoesNotThrow(() -> tucPki018Verifier.performTucPki18Checks(cert));
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = "invalid")
  void verifyPerformTucPki18ChecksInvalid(final X509Certificate cert) {
    configureOcspResponderMockForOcspRequest(cert, ocspResponderMock);
    assertThatThrownBy(() -> tucPki018Verifier.performTucPki18Checks(cert))
        .as("Test invalid certificates")
        .isInstanceOf(GemPkiException.class);
  }
}
