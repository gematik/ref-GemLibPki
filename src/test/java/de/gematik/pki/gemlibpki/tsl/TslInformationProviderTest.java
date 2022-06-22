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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.pki.gemlibpki.utils.ResourceReader;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.util.Collections;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslInformationProviderTest {

  private static final String FILE_NAME_TSL_DEFAULT = "tsls/valid/TSL-test.xml";
  private TslInformationProvider tslInformationProvider;

  @BeforeEach
  void setUp() {
    final Optional<TrustStatusListType> tsl =
        TslReader.getTsl(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT));
    tslInformationProvider = new TslInformationProvider(tsl.orElseThrow());
  }

  @Test
  void readTspServices_PkcProviderSizeShouldBeCorrect() {
    assertThat(
            tslInformationProvider.getFilteredTspServices(
                Collections.singletonList(TslConstants.STI_PKC)))
        .hasSize(83);
  }

  @Test
  void readAllTspServices_providerSizeShouldBeCorrect() {
    assertThat(tslInformationProvider.getTspServices()).hasSize(152);
  }
}
