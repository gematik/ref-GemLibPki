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

import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.GEMATIK_TEST_TSP_NAME;
import static de.gematik.pki.gemlibpki.commons.tsl.TslConstants.STI_CA_LIST;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslInformationProviderTest {

  private TslInformationProvider tslInformationProviderNonQes;
  private TslInformationProvider tslInformationProviderQes;

  @BeforeEach
  void setUp() {
    tslInformationProviderNonQes =
        new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes());
    tslInformationProviderQes = new TslInformationProvider(TestUtils.getDefaultTslUnsignedQes());
  }

  @Test
  void getFilteredTspServices_whenFilteringForPkcInNonQesTsl_thenReturnsExpectedNumberServices() {
    assertThat(
            tslInformationProviderNonQes.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_PKC)))
        .hasSize(88);
  }

  @Test
  void getTspServices_whenProviderHasNoServices_thenIgnoresProvider() {
    final TrustStatusListType defaultTsl = TestUtils.getDefaultTslUnsignedNonQes();

    // baseline: number of services in the default TSL
    final int baselineSize =
        new TslInformationProvider(TestUtils.getDefaultTslUnsignedNonQes()).getTspServices().size();

    // add a provider without TSPServices (null) -> should be ignored by getTspServices()
    defaultTsl.getTrustServiceProviderList().getTrustServiceProvider().add(new TSPType());

    final var result = new TslInformationProvider(defaultTsl).getTspServices();

    org.assertj.core.api.Assertions.assertThat(result).hasSize(baselineSize);
  }

  @Test
  void getTspServices_whenProvidersHaveEmptyOrNullServices_thenReturnsEmptyLists() {
    // with services empty
    final TrustStatusListType tslQesWithoutTspService = TestUtils.getDefaultTslUnsignedNonQes();
    tslQesWithoutTspService
        .getTrustServiceProviderList()
        .getTrustServiceProvider()
        .forEach(tspType -> tspType.getTSPServices().getTSPService().clear());

    final TslInformationProvider tslInformationProvider =
        new TslInformationProvider(tslQesWithoutTspService);
    assertThat(tslInformationProvider.getTspServices()).isEmpty();
    assertThat(
            tslInformationProvider.getTspServicesForTsp(
                GEMATIK_TEST_TSP_NAME, Collections.singletonList(TslConstants.STI_QC)))
        .isEmpty();

    // with services null
    tslQesWithoutTspService
        .getTrustServiceProviderList()
        .getTrustServiceProvider()
        .forEach(tspType -> tspType.setTSPServices(null));
    final TslInformationProvider tslInformationProviderNullServices =
        new TslInformationProvider(tslQesWithoutTspService);
    assertThat(tslInformationProviderNullServices.getTspServices()).isEmpty();
    assertThat(
            tslInformationProvider.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_QC)))
        .isEmpty();
  }

  @Test
  void getFilteredTspServices_whenFilteringForPkcInQesTsl_thenReturnsEmptyList() {
    assertThat(
            tslInformationProviderQes.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_PKC)))
        .isEmpty();
  }

  @Test
  void
      getFilteredTspServices_whenFilteringForUnspecifiedInNonQesTsl_thenReturnsExpectedNumberOfServices() {
    assertThat(
            tslInformationProviderNonQes.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_UNSPECIFIED)))
        .hasSize(20);
  }

  @Test
  void getFilteredTspServices_whenFilteringForQcInNonQesTsl_thenReturnsEmptyList() {
    assertThat(
            tslInformationProviderNonQes.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_QC)))
        .isEmpty();
  }

  @Test
  void getFilteredTspServices_whenFilteringForQcInQesTsl_thenReturnsExpectedNumberOfServices() {
    assertThat(
            tslInformationProviderQes.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_QC)))
        .hasSize(401);
  }

  @Test
  void getFilteredTspServices_whenFilteringForCrlInNonQesTsl_thenReturnsExpectedNumberOfServices() {
    assertThat(
            tslInformationProviderNonQes.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_CRL)))
        .hasSize(1);
  }

  @Test
  void getTspServices_whenNonQesTslIsProvided_thenReturnsExpectedNumberOfServices() {
    assertThat(tslInformationProviderNonQes.getTspServices()).hasSize(183);
  }

  @Test
  void getTspServices_whenQesTslIsProvided_thenReturnsExpectedNumberOfServices() {
    assertThat(tslInformationProviderQes.getTspServices()).hasSize(863);
  }

  @Test
  void tslInformationProviderMethods_whenRequiredArgumentsAreNull_thenFailFast() {
    assertNonNullParameter(
        () -> tslInformationProviderNonQes.getFilteredTspServices(null), "stiFilterList");

    assertNonNullParameter(
        () -> tslInformationProviderNonQes.getTspServicesForTsp(null, STI_CA_LIST), "tsp");
    assertNonNullParameter(
        () -> tslInformationProviderNonQes.getTspServicesForTsp(GEMATIK_TEST_TSP_NAME, null),
        "stiFilterList");
  }
}
