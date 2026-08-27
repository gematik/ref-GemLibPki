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

package de.gematik.pki.gemlibpki.commons.certificate;

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.INVALID_CERT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.OCSP_HOST;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_HBA_AUT_ECC;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_EGK;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_HBA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_KOMP_CA41;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_KOMP_CA51;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_KOMP_CA57;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_KOMP_CA61;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_ISSUER_CERT_SMCB_CA41_RSA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_INVALID_KEY_USAGE;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB_CA41_RSA;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_ANY;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_AK_AUT_ECC;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_CH_AUT_ECC;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_FD_OSIG;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_FD_SIG;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_FD_TLS_C_ECC;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_FD_TLS_S_RSA;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_RSA;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_HCI_OSIG;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_HP_AUT_ECC;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_TSL_SIG;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_BUNDESWEHRAPOTHEKE;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_KOSTENTRAEGER;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_KRANKENHAUS;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_KRANKENHAUSAPOTHEKE;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_MOBILE_EINRICHTUNG_RETTUNGSDIENST;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_OEFFENTLICHE_APOTHEKE;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_PRAXIS_ARZT;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_PRAXIS_PSYCHOTHERAPEUT;
import static de.gematik.pki.gemlibpki.commons.certificate.Role.OID_ZAHNARZTPRAXIS;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.overwriteSspUrls;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.readCertNonQes;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiParsingException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRequestGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponderMock;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponseGenerator;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTestConstants;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.commons.utils.CertificateProvider;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import de.gematik.pki.gemlibpki.commons.utils.VariableSource;
import de.gematik.pki.gemlibpki.ti10.ocsp.TslBasedSspOcspTransceiverFactory;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TucPki018VerifierTest {

  private static final List<CertificateProfile> certificateProfiles =
      List.of(CERT_PROFILE_C_HCI_AUT_ECC);
  private static final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;
  private static final int OCSP_GRACE_PERIOD_30_SECONDS = 30;
  private static final int SECONDS_5_AS_MILLISECS = 5000;
  private static final int SECONDS_50_AS_MILLISECS = 50000;

  private final OcspResponderMock ocspResponderMock =
      OcspResponderMock.createAndStart(LOCAL_SSP_DIR, OCSP_HOST, null);
  private TucPki018Verifier tucPki018Verifier;
  private OcspRespCache ocspRespCache;

  private boolean tolerateOcspFailure;

  @AfterAll
  void tearDown() {
    ocspResponderMock.stop();
  }

  @BeforeEach
  void init() {
    ocspRespCache = new OcspRespCache(OCSP_GRACE_PERIOD_30_SECONDS);

    tolerateOcspFailure = false;
    tucPki018Verifier = buildTucPki18Verifier(certificateProfiles);
  }

  private TucPki018Verifier buildTucPki18Verifier(
      final List<CertificateProfile> certificateProfiles) {

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    overwriteSspUrls(tspServiceList, ocspResponderMock.getSspUrl());

    return TucPki018Verifier.builder()
        .productType(PRODUCT_TYPE)
        .tspServiceList(tspServiceList)
        .certificateProfiles(certificateProfiles)
        .ocspRespCache(ocspRespCache)
        .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_30_SECONDS * 1000)
        .ocspTimeoutSeconds(ocspTimeoutSeconds)
        .tolerateOcspFailure(tolerateOcspFailure)
        .build();
  }

  @Test
  void
      performTucPki018Checks_whenCertificateAndOcspResponseAreValid_thenCompletesWithoutException() {

    ocspResponderMock.configureForOcspRequest(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    assertDoesNotThrow(() -> tucPki018Verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB));
  }

  @Test
  void performTucPki018Checks_whenOcspCheckIsDisabled_thenCompletesWithoutException() {
    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();
    overwriteSspUrls(tspServiceList, "invalidSsp");
    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspRespCache(ocspRespCache)
            .withOcspCheck(false)
            .build();
    assertDoesNotThrow(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB));
  }

  @Test
  void performTucPki018Checks_whenOcspTranseiverIsGiven_thenCompletesWithoutException()
      throws GemPkiException {
    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();
    overwriteSspUrls(tspServiceList, ocspResponderMock.getSspUrl());
    final X509Certificate eeCert = VALID_X509_EE_CERT_SMCB;

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspRespCache(ocspRespCache)
            .ocspTransceiver(
                new TslBasedSspOcspTransceiverFactory(
                        PRODUCT_TYPE, tspServiceList, ocspTimeoutSeconds, tolerateOcspFailure)
                    .create(eeCert))
            .build();
    ocspResponderMock.configureForOcspRequest(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    assertDoesNotThrow(() -> verifier.performTucPki018Checks(eeCert));
  }

  @Test
  void performTucPki018Checks_whenServiceSupplyPointIsMissing_thenThrowsGemPkiException() {

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    tspServiceList.forEach(
        tspService ->
            tspService
                .getTspServiceType()
                .getServiceInformation()
                .getServiceSupplyPoints()
                .getServiceSupplyPoint()
                .removeIf(ssp -> true));

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspRespCache(ocspRespCache)
            .build();

    assertThatThrownBy(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1026_SERVICESUPPLYPOINT_MISSING.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      performTucPki018Checks_whenAnyCertificateProfileIsConfigured_thenCompletesWithoutException() {
    ocspResponderMock.configureForOcspRequest(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CERT_PROFILE_ANY))
                .performTucPki018Checks(VALID_X509_EE_CERT_SMCB));
  }

  @Test
  void performTucPki018Checks_whenAkAutEccCertificateIsValid_thenCompletesWithoutException() {
    final X509Certificate eeCert =
        readCertNonQes("GEM.KOMP-CA57/80276883110000000001-20250721_ecc.crt");
    ocspResponderMock.configureForOcspRequest(eeCert, VALID_ISSUER_CERT_KOMP_CA57);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CERT_PROFILE_C_AK_AUT_ECC))
                .performTucPki018Checks(eeCert));
  }

  @Test
  void checkAllowedProfessionOids_whenAdmissionContainsAllowedOid_thenReturnsTrue()
      throws IOException {
    // var names und einmal admission aus dem tuckverifiey
    final Set<String> allowedProfOids =
        Set.of(
            OID_PRAXIS_ARZT.getProfessionOid(),
            OID_ZAHNARZTPRAXIS.getProfessionOid(),
            OID_PRAXIS_PSYCHOTHERAPEUT.getProfessionOid(),
            OID_KRANKENHAUS.getProfessionOid(),
            OID_OEFFENTLICHE_APOTHEKE.getProfessionOid(),
            OID_KRANKENHAUSAPOTHEKE.getProfessionOid(),
            OID_BUNDESWEHRAPOTHEKE.getProfessionOid(),
            OID_MOBILE_EINRICHTUNG_RETTUNGSDIENST.getProfessionOid(),
            OID_KOSTENTRAEGER.getProfessionOid());
    final Admission admission = new Admission(VALID_X509_EE_CERT_SMCB);

    assertTrue(() -> TucPki018Verifier.checkAllowedProfessionOids(admission, allowedProfOids));
  }

  @Test
  void checkAllowedProfessionOids_whenAdmissionContainsNoAllowedOid_thenReturnsFalse()
      throws IOException {
    final Set<String> allowedProfOids = Set.of(OID_KOSTENTRAEGER.getProfessionOid());
    final Admission admission = new Admission(VALID_X509_EE_CERT_SMCB);

    assertFalse(() -> TucPki018Verifier.checkAllowedProfessionOids(admission, allowedProfOids));
  }

  @Test
  void checkAllowedProfessionOids_whenAdmissionContainsNoProfessionOid_thenReturnsFalse()
      throws IOException {
    final X509Certificate missingProfOid =
        TestUtils.readCertNonQes("GEM.SMCB-CA57/valid/BabetteBeyer-missing-prof-oid.pem");
    final Set<String> allowdProfOids = Set.of(OID_PRAXIS_PSYCHOTHERAPEUT.getProfessionOid());
    final Admission admission = new Admission(missingProfOid);

    assertFalse(() -> TucPki018Verifier.checkAllowedProfessionOids(admission, allowdProfOids));
  }

  @Test
  void checkAllowedProfessionOids_whenAdmissionExtensionIsMissing_thenReturnsFalse()
      throws IOException {
    final X509Certificate missingAdmission =
        TestUtils.readCertNonQes("GEM.SMCB-CA57/valid/BabetteBeyer-missing-admission.pem");
    final Set<String> allowedProfOids = Set.of(OID_PRAXIS_PSYCHOTHERAPEUT.getProfessionOid());
    final Admission admission = new Admission(missingAdmission);

    assertFalse(() -> TucPki018Verifier.checkAllowedProfessionOids(admission, allowedProfOids));
  }

  @Test
  void
      checkAllowedProfessionOids_whenAdmissionIsNull_thenReturnsFalseAndRejectsNullAllowedProfessionOids()
          throws IOException {
    final Set<String> allowedProfOids = Set.of(OID_PRAXIS_PSYCHOTHERAPEUT.getProfessionOid());
    final Admission admission = new Admission(VALID_X509_EE_CERT_SMCB);

    assertFalse(() -> TucPki018Verifier.checkAllowedProfessionOids(null, allowedProfOids));
    assertNonNullParameter(
        () -> TucPki018Verifier.checkAllowedProfessionOids(admission, null),
        "allowedProfessionOids");
  }

  @Test
  void performTucPki018Checks_whenNistCertificateIsValid_thenCompletesWithoutException() {
    final X509Certificate eeNistCert = readCertNonQes("GEM.KOMP-CA61/ee_komp_nist_test.pem");
    final X509Certificate validNistIssuer =
        readCertNonQes("GEM.KOMP-CA61/GEM.KOMP-CA61-TEST-ONLY.pem");
    ocspResponderMock.configureForOcspRequest(eeNistCert, validNistIssuer);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CERT_PROFILE_C_FD_TLS_C_ECC))
                .performTucPki018Checks(eeNistCert));
  }

  @Test
  void performTucPki018Checks_whenEgkAutEccCertificateIsValid_thenCompletesWithoutException() {
    final X509Certificate eeCert = readCertNonQes("GEM.EGK-CA51/LetitiaBeutelsbacher.pem");
    ocspResponderMock.configureForOcspRequest(eeCert, VALID_ISSUER_CERT_EGK);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CERT_PROFILE_C_CH_AUT_ECC))
                .performTucPki018Checks(eeCert));
  }

  @Test
  void performTucPki018Checks_whenHbaAutEccCertificateIsValid_thenCompletesWithoutException() {

    ocspResponderMock.configureForOcspRequest(VALID_HBA_AUT_ECC, VALID_ISSUER_CERT_HBA);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CERT_PROFILE_C_HP_AUT_ECC))
                .performTucPki018Checks(VALID_HBA_AUT_ECC));
  }

  @Test
  void performTucPki018Checks_whenSmcbAutRsaCertificateIsValid_thenCompletesWithoutException() {

    ocspResponderMock.configureForOcspRequest(
        VALID_X509_EE_CERT_SMCB_CA41_RSA, VALID_ISSUER_CERT_SMCB_CA41_RSA);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CERT_PROFILE_C_HCI_AUT_RSA))
                .performTucPki018Checks(VALID_X509_EE_CERT_SMCB_CA41_RSA));
  }

  @Test
  void performTucPki018Checks_whenFdSigCertificateIsValid_thenCompletesWithoutException() {
    final X509Certificate eeCert = readCertNonQes("GEM.KOMP-CA51/fdsig_erezept.pem");
    ocspResponderMock.configureForOcspRequest(eeCert, VALID_ISSUER_CERT_KOMP_CA51);
    assertDoesNotThrow(
        () -> buildTucPki18Verifier(List.of(CERT_PROFILE_C_FD_SIG)).performTucPki018Checks(eeCert));
  }

  @Test
  void performTucPki018Checks_whenFdOsigCertificateIsValid_thenCompletesWithoutException() {
    final X509Certificate eeCert = readCertNonQes("GEM.KOMP-CA61/nist_test_fd_osig.pem");
    ocspResponderMock.configureForOcspRequest(eeCert, VALID_ISSUER_CERT_KOMP_CA61);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CERT_PROFILE_C_FD_OSIG)).performTucPki018Checks(eeCert));
  }

  @Test
  void performTucPki018Checks_whenFdTlsSRsaCertificateIsValid_thenCompletesWithoutException() {
    final X509Certificate eeCert = readCertNonQes("GEM.KOMP-CA41/tp-fqdn-test-rsa.pem");

    ocspResponderMock.configureForOcspRequest(eeCert, VALID_ISSUER_CERT_KOMP_CA41);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(List.of(CERT_PROFILE_C_FD_TLS_S_RSA))
                .performTucPki018Checks(eeCert));
  }

  @Test
  void performTucPki018Checks_whenProfessionOidsArePresent_thenReturnsProfessionOids()
      throws GemPkiException {
    final X509Certificate eeCert =
        readCertNonQes("GEM.SMCB-CA41-RSA/80276001011699901340-C_SMCB_OSIG_R2048_X509.pem");
    ocspResponderMock.configureForOcspRequest(eeCert, VALID_ISSUER_CERT_SMCB_CA41_RSA);

    assertThat(
            buildTucPki18Verifier(List.of(CERT_PROFILE_C_HCI_OSIG))
                .performTucPki018Checks(eeCert)
                .getProfessionOids())
        .contains(OID_KRANKENHAUS.getProfessionOid());
  }

  @Test
  void performTucPki018Checks_whenMultipleProfilesMatch_thenSelectsCorrectOne() {
    ocspResponderMock.configureForOcspRequest(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    assertDoesNotThrow(
        () ->
            buildTucPki18Verifier(
                    List.of(
                        CERT_PROFILE_C_TSL_SIG,
                        CERT_PROFILE_C_HCI_AUT_RSA,
                        CERT_PROFILE_C_HCI_AUT_ECC))
                .performTucPki018Checks(VALID_X509_EE_CERT_SMCB));
  }

  @Test
  void
      performTucPki018Checks_whenMultipleProfilesHaveWrongKeyUsage_thenThrowsGemPkiParsingException() {

    ocspResponderMock.configureForOcspRequest(
        VALID_X509_EE_CERT_INVALID_KEY_USAGE, VALID_ISSUER_CERT_SMCB);
    final TucPki018Verifier verifier =
        buildTucPki18Verifier(List.of(CERT_PROFILE_C_HCI_AUT_ECC, CERT_PROFILE_C_HP_AUT_ECC));
    assertThatThrownBy(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_INVALID_KEY_USAGE))
        .isInstanceOf(GemPkiParsingException.class)
        .hasMessageContaining(ErrorCode.SE_1016_WRONG_KEYUSAGE.name());
  }

  @Test
  void
      performTucPki018Checks_whenMultipleProfilesDoNotMatchCertificateType_thenThrowsGemPkiParsingException() {
    ocspResponderMock.configureForOcspRequest(INVALID_CERT_TYPE, VALID_ISSUER_CERT_SMCB);
    final TucPki018Verifier verifier =
        buildTucPki18Verifier(List.of(CERT_PROFILE_C_HCI_AUT_ECC, CERT_PROFILE_C_HP_AUT_ECC));
    assertThatThrownBy(() -> verifier.performTucPki018Checks(INVALID_CERT_TYPE))
        .isInstanceOf(GemPkiParsingException.class)
        .hasMessageContaining(ErrorCode.SE_1018_CERT_TYPE_MISMATCH.name())
        .hasMessageContaining(ErrorCode.SE_1016_WRONG_KEYUSAGE.name());
  }

  @Test
  void performTucPki018ChecksAndHelperMethods_whenParametersAreNull_thenThrowsNullPointerException()
      throws GemPkiException {

    assertNonNullParameter(() -> tucPki018Verifier.performTucPki018Checks(null), "x509EeCert");
    assertNonNullParameter(
        () -> tucPki018Verifier.performTucPki018Checks(null, GemLibPkiUtils.now()), "x509EeCert");
    assertNonNullParameter(
        () -> tucPki018Verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, null),
        "referenceDate");

    assertNonNullParameter(() -> buildTucPki18Verifier(null), "certificateProfiles");

    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(
                new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes())
                    .getTspServices(),
                PRODUCT_TYPE)
            .getIssuerTspServiceSubset(VALID_X509_EE_CERT_SMCB);

    assertNonNullParameter(
        () -> tucPki018Verifier.tucPki018ProfileChecks(null, tspServiceSubset), "x509EeCert");

    assertNonNullParameter(
        () -> tucPki018Verifier.tucPki018ProfileChecks(VALID_X509_EE_CERT_SMCB, null),
        "tspServiceSubset");

    assertNonNullParameter(
        () ->
            tucPki018Verifier.tucPki018ChecksForProfile(
                null, CERT_PROFILE_C_HCI_AUT_ECC, tspServiceSubset),
        "x509EeCert");
    assertNonNullParameter(
        () ->
            tucPki018Verifier.tucPki018ChecksForProfile(
                VALID_X509_EE_CERT_SMCB, null, tspServiceSubset),
        "certificateProfile");

    assertNonNullParameter(
        () ->
            tucPki018Verifier.tucPki018ChecksForProfile(
                VALID_X509_EE_CERT_SMCB, CERT_PROFILE_C_HCI_AUT_ECC, null),
        "tspServiceSubset");

    final ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

    assertNonNullParameter(
        () -> tucPki018Verifier.commonChecks(null, tspServiceSubset, now), "x509EeCert");

    assertNonNullParameter(
        () -> tucPki018Verifier.commonChecks(VALID_X509_EE_CERT_SMCB, null, now),
        "tspServiceSubset");

    assertNonNullParameter(
        () -> tucPki018Verifier.commonChecks(VALID_X509_EE_CERT_SMCB, tspServiceSubset, null),
        "referenceDate");

    assertNonNullParameter(() -> tucPki018Verifier.doOcspIfConfigured(null, now), "x509EeCert");

    assertNonNullParameter(
        () -> tucPki018Verifier.doOcspIfConfigured(VALID_X509_EE_CERT_SMCB, null), "referenceDate");
  }

  @Test
  void performTucPki018Checks_whenCertificateProfilesAreEmpty_thenThrowsGemPkiRuntimeException() {
    ocspResponderMock.configureForOcspRequest(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final TucPki018Verifier verifier = buildTucPki18Verifier(List.of());
    assertThatThrownBy(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Liste der konfigurierten Zertifikatsprofile ist leer.");
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = "valid")
  void
      performTucPki018Checks_whenValidCertificateFromProviderIsProvided_thenCompletesWithoutException(
          final X509Certificate cert) {
    ocspResponderMock.configureForOcspRequest(cert, VALID_ISSUER_CERT_SMCB);
    assertDoesNotThrow(() -> tucPki018Verifier.performTucPki018Checks(cert));
  }

  @ParameterizedTest
  @ArgumentsSource(CertificateProvider.class)
  @VariableSource(value = "invalid")
  void
      performTucPki018Checks_whenInvalidCertificateFromProviderIsProvided_thenThrowsGemPkiException(
          final X509Certificate cert) {
    ocspResponderMock.configureForOcspRequest(cert, VALID_ISSUER_CERT_SMCB);
    assertThatThrownBy(() -> tucPki018Verifier.performTucPki018Checks(cert))
        .as("Test invalid certificates")
        .isInstanceOf(GemPkiException.class);
  }

  @Test
  void performTucPki018Checks_whenOcspTimeoutIsZero_thenThrowsGemPkiException() {

    ocspResponderMock.configureForOcspRequest(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    overwriteSspUrls(tspServiceList, ocspResponderMock.getSspUrl());

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspRespCache(ocspRespCache)
            .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_30_SECONDS * 1000)
            .ocspTimeoutSeconds(0)
            .tolerateOcspFailure(false)
            .build();

    assertThatThrownBy(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1032_OCSP_NOT_AVAILABLE.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki018Checks_whenOcspProducedAtExceedsPastTolerance_thenThrowsGemPkiException() {
    final int ocspGracePeriod10Seconds = 10;
    final int ocspTimeToleranceProducedAtPastMilliseconds = ocspGracePeriod10Seconds * 1000;

    ocspResponderMock.configureForOcspRequestProducedAt(
        VALID_X509_EE_CERT_SMCB,
        VALID_ISSUER_CERT_SMCB,
        -(ocspTimeToleranceProducedAtPastMilliseconds + 1));

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    overwriteSspUrls(tspServiceList, ocspResponderMock.getSspUrl());

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspRespCache(new OcspRespCache(ocspGracePeriod10Seconds))
            .ocspTimeToleranceProducedAtPastMilliseconds(
                ocspTimeToleranceProducedAtPastMilliseconds)
            .tolerateOcspFailure(false)
            .build();

    assertThatThrownBy(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void performTucPki018Checks_whenProvidedOcspResponseIsValid_thenCompletesWithoutException() {
    final ZonedDateTime referenceDate = ZonedDateTime.parse("2025-05-13T15:00:00Z");

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

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(
        () -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate));
  }

  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseIsValidAndCustomPastToleranceIsConfigured_thenCompletesWithoutException() {
    final int SECONDS_10_AS_MILLISECS = 10000;
    final ZonedDateTime referenceDate = ZonedDateTime.parse("2025-03-20T15:00:00Z");

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

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtPastMilliseconds(SECONDS_10_AS_MILLISECS)
            .build();

    assertDoesNotThrow(
        () -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate));
  }

  /**
   * Verifies that {@link TucPki018Verifier#performTucPki018Checks(X509Certificate, ZonedDateTime)}
   * handles the custom tolerance correctly when the producedAt time is in the future. Without
   * setting .ocspTimeToleranceProducedAtFutureMilliseconds(SECONDS_50_AS_MILLISECS) an exception
   * would be thrown, because the producedAt time is more seconds in the future than the default
   * tolerance.
   */
  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseProducedAtIsInFuture_thenCustomToleranceAllowsValidationAndDefaultToleranceThrows() {
    final ZonedDateTime referenceDate = ZonedDateTime.parse("2025-03-20T15:00:00Z");

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(GemLibPkiUtils.now().plusSeconds(45))
            .nextUpdate(GemLibPkiUtils.now().plusMinutes(5))
            .thisUpdate(GemLibPkiUtils.now().minusSeconds(45))
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifierPass =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtFutureMilliseconds(SECONDS_50_AS_MILLISECS)
            .build();

    assertDoesNotThrow(
        () -> verifierPass.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate));

    final TucPki018Verifier verifierFail =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .build();

    assertThatThrownBy(
            () -> verifierFail.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseProducedAtExceedsCustomFutureTolerance_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(GemLibPkiUtils.now().plusSeconds(50))
            .nextUpdate(referenceDate.plusMinutes(1))
            .thisUpdate(referenceDate.minusSeconds(45))
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtPastMilliseconds(SECONDS_50_AS_MILLISECS)
            .build();

    assertThatThrownBy(
            () -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseUsesDefaultTolerance_thenCompletesWithoutException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now();

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(referenceDate)
            .nextUpdate(referenceDate)
            .thisUpdate(referenceDate.minusSeconds(35))
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(
        () -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate));
  }

  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseThisUpdateIsInPast_thenCompletesWithoutException() {
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
    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();
    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .build();
    assertDoesNotThrow(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, thisUpdate));
  }

  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseProducedAtIsFarInFutureAndDefaultToleranceIsUsed_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime thisUpdate = referenceDate;
    final ZonedDateTime producedAt = referenceDate.plusSeconds(3601);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(producedAt)
            .nextUpdate(referenceDate)
            .thisUpdate(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .build();

    assertThatThrownBy(
            () -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class);
  }

  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseProducedAtExceedsTenSecondFutureTolerance_thenThrowsGemPkiException() {
    final int SECONDS_10_AS_MILLISECS = 10000;
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime thisUpdate = referenceDate;
    final ZonedDateTime producedAt = referenceDate.plusSeconds(12);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(producedAt)
            .nextUpdate(referenceDate)
            .thisUpdate(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtFutureMilliseconds(SECONDS_10_AS_MILLISECS)
            .build();

    assertThatThrownBy(
            () -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class);
  }

  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseProducedAtExceedsFiveSecondFutureTolerance_thenThrowsGemPkiException() {
    final ZonedDateTime referenceDate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime thisUpdate = referenceDate;
    final ZonedDateTime producedAt = referenceDate.plusSeconds(10);

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEccNonQes())
            .producedAt(producedAt)
            .nextUpdate(referenceDate)
            .thisUpdate(thisUpdate)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .ocspTimeToleranceProducedAtFutureMilliseconds(SECONDS_5_AS_MILLISECS)
            .build();

    assertThatThrownBy(
            () -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceDate))
        .isInstanceOf(GemPkiException.class);
  }

  @Test
  void performTucPki018Checks_whenProvidedOcspResponseNextUpdateIsExpired_thenIgnoresNextUpdate() {

    final ZonedDateTime referenceDate = GemLibPkiUtils.now().minusSeconds(40);

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

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .build();

    assertDoesNotThrow(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB));
  }

  /**
   * Verifies that the given OCSP response with certStatus revoked is enough for a certificate to be
   * considered valid. Then it verifies that the given OCSP response is stored in the cache and is
   * enough for a certificate to be considered valid again. Furthermore, it verifies that OCSP
   * response in the cache is validated again because of another reference time which is after the
   * revocation time.
   */
  @Test
  void
      performTucPki018Checks_whenProvidedRevokedOcspResponseIsValidForReferenceTime_thenCompletesWithoutException() {
    final ZonedDateTime thisUpdate = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime producedAt = ZonedDateTime.now(ZoneOffset.UTC);
    final ZonedDateTime nextUpdate = ZonedDateTime.now(ZoneOffset.UTC).plusSeconds(30);
    final ZonedDateTime revocationTime = ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(10);
    final ZonedDateTime referenceTime = ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(30);

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

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .ocspRespCache(new OcspRespCache(OCSP_GRACE_PERIOD))
            .build();

    assertDoesNotThrow(
        () -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB, referenceTime));
  }

  @Test
  void
      performTucPki018Checks_whenProvidedOcspResponseIsInvalidAndOnlineResponseIsValid_thenCompletesWithoutException() {

    ocspResponderMock.configureForOcspRequest(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

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

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceListNonQes();

    overwriteSspUrls(tspServiceList, ocspResponderMock.getSspUrl());

    final TucPki018Verifier verifier =
        TucPki018Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tspServiceList(tspServiceList)
            .certificateProfiles(certificateProfiles)
            .ocspResponse(ocspResp)
            .build();

    // TECHNICAL_WARNING TW_1050_PROVIDED_OCSP_RESPONSE_NOT_VALID
    assertDoesNotThrow(() -> verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB));
  }

  @Test
  void
      performTucPki018Checks_whenAdmissionProcessingThrowsIOException_thenThrowsGemPkiRuntimeException()
          throws GemPkiException {

    ocspResponderMock.configureForOcspRequest(VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);

    try (final MockedConstruction<Admission> ignored =
        Mockito.mockConstructionWithAnswer(
            Admission.class,
            invocation -> {
              throw new IOException();
            })) {

      final Admission admission = tucPki018Verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB);
      assertThat(admission).isNull();
    }
  }
}
