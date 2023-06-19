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
    tslInformationProvider = new TslInformationProvider(TestUtils.getDefaultTsl());
  }

  @Test
  void readTspServices_PkcProviderSizeShouldBeCorrect() {
    assertThat(
            tslInformationProvider.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_PKC)))
        .hasSize(135);
  }

  @Test
  void readAllTspServices_providerSizeShouldBeCorrect() {
    assertThat(tslInformationProvider.getTspServices()).hasSize(271);
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
