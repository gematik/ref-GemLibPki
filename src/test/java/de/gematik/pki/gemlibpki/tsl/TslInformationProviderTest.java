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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.GEMATIK_TEST_TSP_NAME;
import static de.gematik.pki.gemlibpki.tsl.TslConstants.STI_CA_LIST;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslInformationProviderTest {

  private TslInformationProvider tslInformationProvider;

  @BeforeEach
  void setUp() {
    tslInformationProvider = new TslInformationProvider(TestUtils.getDefaultTslUnsigned());
  }

  @Test
  void readTspServices_PkcServicesSizeShouldBeCorrect() {
    assertThat(
            tslInformationProvider.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_PKC)))
        .hasSize(138);
  }

  @Test
  void readTspServices_UnspecifiedServicesSizeShouldBeCorrect() {
    assertThat(
            tslInformationProvider.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_UNSPECIFIED)))
        .hasSize(26);
  }

  @Test
  void readTspServices_QcServicesProviderSizeShouldBeCorrect() {
    assertThat(
            tslInformationProvider.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_QC)))
        .isEmpty();
  }

  @Test
  void readTspServices_CrlServicesProviderSizeShouldBeCorrect() {
    assertThat(
            tslInformationProvider.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_CRL)))
        .hasSize(3);
  }

  @Test
  void readAllTspServices_ServicesSizeShouldBeCorrect() {
    assertThat(tslInformationProvider.getTspServices()).hasSize(283);
  }

  @Test
  void nonNull() {
    assertNonNullParameter(
        () -> tslInformationProvider.getFilteredTspServices(null), "stiFilterList");

    assertNonNullParameter(
        () -> tslInformationProvider.getTspServicesForTsp(null, STI_CA_LIST), "tsp");
    assertNonNullParameter(
        () -> tslInformationProvider.getTspServicesForTsp(GEMATIK_TEST_TSP_NAME, null),
        "stiFilterList");
  }
}
