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

import static de.gematik.pki.gemlibpki.commons.TestConstantsNonQes.FILE_NAME_TSL_DEFAULT_NON_QES;
import static de.gematik.pki.gemlibpki.commons.tsl.TslWriter.STATUS_LIST_TO_FILE_FAILED;
import static de.gematik.pki.gemlibpki.commons.utils.ResourceReader.getFilePathFromResources;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.assertXmlEqual;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import javax.xml.parsers.ParserConfigurationException;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TslWriterTest {

  @Test
  void writeUnsigned_whenTrustStatusListIsProvided_thenWritesEquivalentXml() {
    final TrustStatusListType tslUnsigned = TestUtils.getDefaultTslUnsignedNonQes();
    final Path destFile = Path.of("target/newTslTssl.xml");
    TslWriter.writeUnsigned(tslUnsigned, destFile);
    assertXmlEqual(getFilePathFromResources(FILE_NAME_TSL_DEFAULT_NON_QES, getClass()), destFile);
  }

  @Test
  void writeUnsigned_whenTargetPathIsInvalid_thenThrowsGemPkiRuntimeException() {
    final TrustStatusListType tsl = TestUtils.getDefaultTslUnsignedNonQes();
    final Path destFile = Path.of("/root/../..");

    assertThatThrownBy(() -> TslWriter.writeUnsigned(tsl, destFile))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(STATUS_LIST_TO_FILE_FAILED);
  }

  @Test
  void write_whenDocumentIsProvided_thenWritesEquivalentXml() {
    final Document tslDoc = TestUtils.getDefaultTslAsDocNonQes();
    final Path destFile = Path.of("target/newTslDoc.xml");
    TslWriter.write(tslDoc, destFile);
    assertXmlEqual(getFilePathFromResources(FILE_NAME_TSL_DEFAULT_NON_QES, getClass()), destFile);
  }

  @Test
  void write_whenTargetPathIsInvalid_thenThrowsGemPkiRuntimeException() {
    final Document tslDoc = TestUtils.getDefaultTslAsDocNonQes();
    final Path destFile = Path.of("/root/../..");

    assertThatThrownBy(() -> TslWriter.write(tslDoc, destFile))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(STATUS_LIST_TO_FILE_FAILED);
  }

  @Test
  void write_whenDocumentAndUnsignedTslRepresentSameContent_thenProducesEqualXml() {
    final TrustStatusListType tslUnsigned = TestUtils.getDefaultTslUnsignedNonQes();
    final Document tslAsDoc = TestUtils.getDefaultTslAsDocNonQes();
    final Path doc = Path.of("target/tslAsDoc.xml");
    final Path tssl = Path.of("target/tslAsTssl.xml");
    TslWriter.write(tslAsDoc, doc);
    TslWriter.writeUnsigned(tslUnsigned, tssl);
    assertXmlEqual(doc, tssl);
  }

  @Test
  void tslToDocUnsigned_whenUnsignedTslIsConverted_thenMatchesDefaultXml() {
    final TrustStatusListType tslUnsigned = TestUtils.getDefaultTslUnsignedNonQes();
    final Path doc = Path.of("target/tslConvertToDoc.xml");
    TslWriter.write(TslConverter.tslToDocUnsigned(tslUnsigned), doc);
    assertXmlEqual(doc, getFilePathFromResources(FILE_NAME_TSL_DEFAULT_NON_QES, getClass()));
  }

  @Test
  void writeMethods_whenRequiredArgumentsAreNull_thenThrowsOnNullParameter()
      throws ParserConfigurationException {
    final Path tslFilePath = Path.of("dummyPath");
    final Document document = TslUtils.createDocBuilder().newDocument();
    final TrustStatusListType tsl = new TrustStatusListType();

    assertNonNullParameter(() -> TslWriter.writeUnsigned(null, tslFilePath), "tslUnsigned");

    assertNonNullParameter(() -> TslWriter.writeUnsigned(tsl, null), "tslFilePath");

    assertNonNullParameter(() -> TslWriter.write(null, tslFilePath), "tslDoc");

    assertNonNullParameter(() -> TslWriter.write(document, null), "tslFilePath");
  }
}
