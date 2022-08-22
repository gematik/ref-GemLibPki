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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.GEMATIK_TEST_TSP_NAME;
import static de.gematik.pki.gemlibpki.tsl.TslConstants.STI_CA_LIST;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.utils.TestUtils;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslInformationProviderTest {

  private TslInformationProvider tslInformationProvider;

  @BeforeEach
  void setUp() {
    tslInformationProvider =
        new TslInformationProvider(TestUtils.getTsl(FILE_NAME_TSL_ECC_DEFAULT));
  }

  @Test
  void readTspServices_PkcProviderSizeShouldBeCorrect() {
    assertThat(
            tslInformationProvider.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_PKC)))
        .hasSize(136);
  }

  @Test
  void readAllTspServices_providerSizeShouldBeCorrect() {
    assertThat(tslInformationProvider.getTspServices()).hasSize(266);
  }

  @Test
  void nonNull() {
    assertThatThrownBy(() -> tslInformationProvider.getFilteredTspServices(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("stiFilterList is marked non-null but is null");

    assertThatThrownBy(() -> tslInformationProvider.getTspServicesForTsp(null, STI_CA_LIST))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsp is marked non-null but is null");
    assertThatThrownBy(
            () -> tslInformationProvider.getTspServicesForTsp(GEMATIK_TEST_TSP_NAME, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("stiFilterList is marked non-null but is null");
  }
}
