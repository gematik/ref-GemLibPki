/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.tsl;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import java.util.Collections;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@Slf4j
class TslInformationProviderTest {

    private static final String FILE_NAME_TSL_DEFAULT = "tsls/valid/TSL_default.xml";
    private static final String STI_PKC = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC";
    private TslInformationProvider tslInformationProvider;

    @BeforeEach
    void setUp() {
        final Optional<TrustServiceStatusList> trustStatusList = new TslReader()
            .getTrustServiceStatusList(FILE_NAME_TSL_DEFAULT);
        tslInformationProvider = new TslInformationProvider(trustStatusList.orElseThrow());
    }

    @Test
    void readTspServices_PkcProviderSizeShouldBeCorrect() {
        assertThat(tslInformationProvider.getTspServices(Collections.singletonList(STI_PKC)).size())
            .isEqualTo(89);
    }

    @Test
    void readTspServices_DefaultListSizeShouldBeCorrect() {
        assertThat(tslInformationProvider.getTspServices().size()).isEqualTo(151);
    }
}
