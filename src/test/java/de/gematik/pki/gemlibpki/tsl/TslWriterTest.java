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

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.tsl.TslWriter.STATUS_LIST_TO_FILE_FAILED;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getFilePathFromResources;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertXmlEqual;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import javax.xml.parsers.ParserConfigurationException;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslWriterTest {

  @Test
  void writeFromTrustServiceStatusList() {
    final TrustStatusListType tsl = TestUtils.getDefaultTsl();
    final Path destFile = Path.of("target/newTslTssl.xml");
    TslWriter.write(tsl, destFile);
    assertXmlEqual(getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT, getClass()), destFile);
  }

  @Test
  void verifyWriteFromTslException() {
    final TrustStatusListType tsl = TestUtils.getDefaultTsl();
    final Path destFile = Path.of("/root/../..");

    assertThatThrownBy(() -> TslWriter.write(tsl, destFile))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(STATUS_LIST_TO_FILE_FAILED);
  }

  @Test
  void writeFromDocument() {
    final Document tslDoc = TestUtils.getDefaultTslAsDoc();
    final Path destFile = Path.of("target/newTslDoc.xml");
    TslWriter.write(tslDoc, destFile);
    assertXmlEqual(getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT, getClass()), destFile);
  }

  @Test
  void verifyWriteFromDocumentException() {
    final Document tslDoc = TestUtils.getDefaultTslAsDoc();
    final Path destFile = Path.of("/root/../..");

    assertThatThrownBy(() -> TslWriter.write(tslDoc, destFile))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(STATUS_LIST_TO_FILE_FAILED);
  }

  @Test
  void verifyWriteDocAndTsslAreEqual() {
    final TrustStatusListType tsl = TestUtils.getDefaultTsl();
    final Document tslAsDoc = TestUtils.getDefaultTslAsDoc();
    final Path doc = Path.of("target/tslAsDoc.xml");
    final Path tssl = Path.of("target/tslAsTssl.xml");
    TslWriter.write(tslAsDoc, doc);
    TslWriter.write(tsl, tssl);
    assertXmlEqual(doc, tssl);
  }

  @Test
  void verifyConvert() {
    final TrustStatusListType tsl = TestUtils.getDefaultTsl();
    final Path doc = Path.of("target/tslConvertToDoc.xml");
    TslWriter.write(TslConverter.tslToDoc(tsl), doc);
    assertXmlEqual(doc, getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT, getClass()));
  }

  @Test
  void nonNullTests() throws ParserConfigurationException {
    final Path tslFilePath = Path.of("dummyPath");
    final Document document = TslUtils.createDocBuilder().newDocument();
    final TrustStatusListType tsl = new TrustStatusListType();

    assertNonNullParameter(() -> TslWriter.write((TrustStatusListType) null, tslFilePath), "tsl");

    assertNonNullParameter(() -> TslWriter.write(tsl, null), "tslFilePath");

    assertNonNullParameter(() -> TslWriter.write((Document) null, tslFilePath), "tslDoc");

    assertNonNullParameter(() -> TslWriter.write(document, null), "tslFilePath");
  }
}
