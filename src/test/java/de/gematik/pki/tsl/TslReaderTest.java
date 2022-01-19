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

package de.gematik.pki.tsl;

import static de.gematik.pki.utils.ResourceReader.getFilePathFromResources;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import de.gematik.pki.exception.GemPkiException;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TslReaderTest {

    private static final String FILE_NAME_TSL_DEFAULT = "tsls/valid/TSL-test.xml";
    private static final String TSL_INVALID_XML = "tsls/defect/TSL_invalid_xmlMalformed_altCA.xml";
    TrustStatusListType tsl;

    @BeforeEach
    void setup() throws GemPkiException, IOException {
        tsl = TslReader.getTsl(getFilePathFromResources(FILE_NAME_TSL_DEFAULT)).orElseThrow();
    }

    @Test
    void verifyGetTrustStatusListTypeIsPresent() throws GemPkiException, IOException {
        assertThat(TslReader.getTsl(getFilePathFromResources(FILE_NAME_TSL_DEFAULT))).isPresent();
    }

    @Test
    void getSequenceNumber() {
        assertThat(TslReader.getSequenceNumber(tsl)).isEqualTo(1018);
    }

    @Test
    void getNextUpdate() {
        assertThat(TslReader.getNextUpdate(tsl)).isNotNull();
    }

    @Test
    void getIssueDate() {
        assertThat(TslReader.getIssueDate(tsl)).isNotNull();
    }

    @Test
    void getTslDownloadUrlPrimary() {
        assertThat(TslReader.getTslDownloadUrlPrimary(tsl)).isEqualTo("http://download-test.tsl.telematik-test/TSL-test.xml");
    }

    @Test
    void getTslDownloadUrlBackup() {
        assertThat(TslReader.getTslDownloadUrlBackup(tsl)).isEqualTo("http://download-bak-test.tsl.telematik-test/TSL-test.xml");
    }

    @Test
    void getOtherTslPointers() {
        final OtherTSLPointersType oTslPtr = TslReader.getOtherTslPointers(tsl);
        assertThat(oTslPtr.getOtherTSLPointer().size()).isEqualTo(2);
        assertThat(((MultiLangStringType) oTslPtr.getOtherTSLPointer().get(0).getAdditionalInformation().getTextualInformationOrOtherInformation()
            .get(0)).getLang()).isEqualTo("DE");
    }

    @Test
    void verifyGetTrustStatusListTypeFailed() {
        assertThatThrownBy(() -> TslReader.getTsl(getFilePathFromResources(TSL_INVALID_XML)))
            .isInstanceOf(GemPkiException.class)
            .hasMessageContaining("Error reading TSL");
    }
}
