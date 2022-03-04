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
import static de.gematik.pki.utils.XmlCompare.documentsAreEqual;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslWriterTest {

    // TSL-test.xml is TU-RSA TSL
    private static final String FILE_NAME_TSL = "tsls/valid/TSL-test.xml";

    @SneakyThrows
    @Test
    void writeFromTrustServiceStatusList() {
        final TrustStatusListType tsl = TslReader.getTsl(getFilePathFromResources(FILE_NAME_TSL)).orElseThrow();
        final Path destFile = Path.of("target/newTslTssl.xml");
        TslWriter.write(tsl, destFile);
        assertThat(documentsAreEqual(getFilePathFromResources(FILE_NAME_TSL), destFile)).isTrue();
    }

    @SneakyThrows
    @Test
    void writeFromDocument() {
        final Document tsl = TslReader.getTslAsDoc(getFilePathFromResources(FILE_NAME_TSL)).orElseThrow();
        final Path destFile = Path.of("target/newTslDoc.xml");
        TslWriter.write(tsl, destFile);
        assertThat(documentsAreEqual(getFilePathFromResources(FILE_NAME_TSL), destFile)).isTrue();
    }

    @SneakyThrows
    @Test
    void verifyWriteDocAndTsslAreEqual() {
        final TrustStatusListType tsl = TslReader.getTsl(getFilePathFromResources(FILE_NAME_TSL)).orElseThrow();
        final Document tslAsDoc = TslReader.getTslAsDoc(getFilePathFromResources(FILE_NAME_TSL)).orElseThrow();
        final Path doc = Path.of("target/tslAsDoc.xml");
        final Path tssl = Path.of("target/tslAsTssl.xml");
        TslWriter.write(tslAsDoc, doc);
        TslWriter.write(tsl, tssl);
        assertThat(documentsAreEqual(doc, tssl)).isTrue();
    }

    @SneakyThrows
    @Test
    void verifyConvert() {
        final TrustStatusListType tsl = TslReader.getTsl(getFilePathFromResources(FILE_NAME_TSL)).orElseThrow();
        final Path doc = Path.of("target/tslConvertToDoc.xml");
        TslWriter.write(TslConverter.tslToDoc(tsl).orElseThrow(), doc);
        assertThat(documentsAreEqual(doc, getFilePathFromResources(FILE_NAME_TSL))).isTrue();
    }


    @Test
    void nonNullTests() {
        assertThatThrownBy(
            () -> TslWriter.write((TrustStatusListType) null, null))
            .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(
            () -> TslWriter.write((Document) null, null))
            .isInstanceOf(NullPointerException.class);
    }
}
