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

package de.gematik.pki.gemlibpki.commons.tsl;

import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_ALT_CA;
import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstantsQes.VALID_X509_EE_CERT_QES;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.xml.datatype.DatatypeFactory;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TspInformationProviderTest {

  private String productType;
  private TspInformationProvider tspInformationProviderNonQes;
  private TspInformationProvider tspInformationProviderQes;

  @BeforeEach
  void setUp() {
    productType = "IDP";
    final TslInformationProvider tslInformationProvider =
        new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes());
    tspInformationProviderNonQes =
        new TspInformationProvider(tslInformationProvider.getTspServices(), productType);
    tspInformationProviderQes =
        new TspInformationProvider(
            new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes()).getTspServices(),
            productType);
  }

  @Test
  void
      getIssuerTspServiceSubset_whenValidEndEntityCertificateIsProvided_thenReturnsWithoutException() {
    assertDoesNotThrow(
        () -> tspInformationProviderNonQes.getIssuerTspServiceSubset(VALID_X509_EE_CERT_SMCB));
    assertDoesNotThrow(
        () -> tspInformationProviderQes.getIssuerTspServiceSubset(VALID_X509_EE_CERT_QES));
  }

  @Test
  void getIssuerTspServiceSubset_whenCertificateIsNull_thenThrowsOnNullParameter() {
    assertNonNullParameter(
        () -> tspInformationProviderNonQes.getIssuerTspServiceSubset(null), "x509EeCert");
    assertNonNullParameter(
        () -> tspInformationProviderNonQes.getIssuerTspServiceSubset(null), "x509EeCert");
  }

  @SneakyThrows
  @Test
  void getIssuerTspService_whenNonQesCertificateIsProvided_thenReturnsTspService() {
    final TspService tspService =
        tspInformationProviderNonQes.getIssuerTspService(VALID_X509_EE_CERT_SMCB);
    assertThat(tspService).isNotNull();
    assertThat(tspService.getTspServiceType()).isNotNull();
  }

  @SneakyThrows
  @Test
  void getIssuerTspService_whenQesCertificateIsProvided_thenReturnsTspService() {
    final TspService tspService =
        tspInformationProviderQes.getIssuerTspService(VALID_X509_EE_CERT_QES);
    assertThat(tspService).isNotNull();
    assertThat(tspService.getTspServiceType()).isNotNull();
  }

  @Test
  void getIssuerTspServiceSubset_whenIssuerCertificateExtractionFails_thenThrowsGemPkiException() {
    final TrustStatusListType tslAltCaBroken =
        TestUtils.getTslUnsigned("tsls/nonqes/defect/TSL_defect_altCA_broken.xml");
    assertThatThrownBy(
            () ->
                new TspInformationProvider(
                        new TslInformationProvider(tslAltCaBroken).getTspServices(), productType)
                    .getIssuerTspServiceSubset(VALID_X509_EE_CERT_ALT_CA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(productType));
  }

  @Test
  void issuerTspServiceLookup_whenIssuerCertificateIsMissing_thenThrowsGemPkiException() {
    assertThatThrownBy(
            () -> tspInformationProviderNonQes.getIssuerTspServiceSubset(VALID_X509_EE_CERT_ALT_CA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1027_CA_CERT_MISSING.getErrorMessage(productType));
    assertThatThrownBy(
            () -> tspInformationProviderQes.getIssuerTspService(VALID_X509_EE_CERT_ALT_CA))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1027_CA_CERT_MISSING.getErrorMessage(productType));
  }

  @Test
  void getIssuerTspServiceSubset_whenAuthorityKeyIdentifierIsMissing_thenThrowsGemPkiException() {
    final X509Certificate invalidx509EeCert =
        TestUtils.readCertNonQes("GEM.SMCB-CA57/invalid/BabetteBeyer-missing-authorityKeyId.pem");
    assertThatThrownBy(
            () -> tspInformationProviderNonQes.getIssuerTspServiceSubset(invalidx509EeCert))
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.SE_1023_AUTHORITYKEYID_DIFFERENT.getErrorMessage(productType));
  }

  @Test
  void
      getIssuerTspServiceSubset_whenIssuerServicesHaveDifferentSupplyPointStates_thenReturnsExpectedSupplyPoints()
          throws GemPkiException {
    assertThat(
            tspInformationProviderNonQes
                .getIssuerTspServiceSubset(VALID_X509_EE_CERT_SMCB)
                .getServiceSupplyPoint())
        .isEqualTo("http://ehca-testref.komp-ca.telematik-test:8080/status/ecc-ocsp");
    assertThat(
            tspInformationProviderQes
                .getIssuerTspServiceSubset(VALID_X509_EE_CERT_QES)
                .getServiceSupplyPoint())
        .isEmpty();
  }

  @SneakyThrows
  @Test
  void getIssuerTspServiceSubset_whenServiceSupplyPointIsMissing_thenReturnsEmptySupplyPoint() {
    final TrustStatusListType tslAltCaMissingSsp =
        TestUtils.getTslUnsigned("tsls/nonqes/defect/TSL_defect_altCA_missingSsp.xml");

    assertThat(
            new TspInformationProvider(
                    new TslInformationProvider(tslAltCaMissingSsp).getTspServices(), productType)
                .getIssuerTspServiceSubset(VALID_X509_EE_CERT_ALT_CA)
                .getServiceSupplyPoint())
        .isEmpty();
  }

  @SneakyThrows
  @Test
  void getIssuerTspServiceSubset_whenServiceSupplyPointIsEmpty_thenReturnsEmptySupplyPoint() {
    final TrustStatusListType tslAltCaEmptySsp =
        TestUtils.getTslUnsigned("tsls/nonqes/defect/TSL_defect_altCA_EmptySsp.xml");

    assertThat(
            new TspInformationProvider(
                    new TslInformationProvider(tslAltCaEmptySsp).getTspServices(), productType)
                .getIssuerTspServiceSubset(VALID_X509_EE_CERT_ALT_CA)
                .getServiceSupplyPoint())
        .isEmpty();
  }

  @Test
  void getIssuerTspService_whenValidCertificateIsProvided_thenReturnsWithoutException() {
    assertDoesNotThrow(
        () -> tspInformationProviderNonQes.getIssuerTspService(VALID_X509_EE_CERT_SMCB));
    assertDoesNotThrow(() -> tspInformationProviderQes.getIssuerTspService(VALID_X509_EE_CERT_QES));
  }

  @Test
  void getIssuerTspService_whenMalformedEntriesArePresent_thenSkipsThem() {
    final List<TspService> tspServicesWithMalformedEntry = new ArrayList<>();
    tspServicesWithMalformedEntry.add(new TspService(new TSPServiceType()));
    tspServicesWithMalformedEntry.addAll(
        new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes()).getTspServices());

    assertDoesNotThrow(
        () ->
            new TspInformationProvider(tspServicesWithMalformedEntry, productType)
                .getIssuerTspService(VALID_X509_EE_CERT_SMCB));
  }

  @SneakyThrows
  @Test
  void getIssuerTspServiceSubset_whenServiceHistoryExists_thenIncludesServiceHistoryEntries() {
    final TspService issuerTspService =
        tspInformationProviderQes.getIssuerTspService(VALID_X509_EE_CERT_QES);
    final ServiceHistoryType serviceHistory = new ServiceHistoryType();
    serviceHistory
        .getServiceHistoryInstance()
        .add(createServiceHistoryInstance(TslConstants.SVCSTATUS_GRANTED, "2024-01-01T00:00:00Z"));
    serviceHistory
        .getServiceHistoryInstance()
        .add(createServiceHistoryInstance(TslConstants.SVCSTATUS_GRANTED, "2023-01-01T00:00:00Z"));
    issuerTspService.getTspServiceType().setServiceHistory(serviceHistory);

    final TspServiceSubset subset =
        new TspInformationProvider(List.of(issuerTspService), productType)
            .getIssuerTspServiceSubset(VALID_X509_EE_CERT_QES);

    assertThat(subset.getServiceStatusHistory())
        .hasSize(2)
        .extracting(
            TspServiceStatusHistoryEntry::serviceStatus,
            historyEntry -> historyEntry.statusStartingTime().toInstant())
        .containsExactly(
            tuple(TslConstants.SVCSTATUS_GRANTED, java.time.Instant.parse("2024-01-01T00:00:00Z")),
            tuple(TslConstants.SVCSTATUS_GRANTED, java.time.Instant.parse("2023-01-01T00:00:00Z")));
  }

  @SneakyThrows
  private ServiceHistoryInstanceType createServiceHistoryInstance(
      final String serviceStatus, final String statusStartingTime) {
    final ServiceHistoryInstanceType serviceHistoryInstance = new ServiceHistoryInstanceType();
    serviceHistoryInstance.setServiceStatus(serviceStatus);
    serviceHistoryInstance.setStatusStartingTime(
        DatatypeFactory.newInstance().newXMLGregorianCalendar(statusStartingTime));
    return serviceHistoryInstance;
  }
}
