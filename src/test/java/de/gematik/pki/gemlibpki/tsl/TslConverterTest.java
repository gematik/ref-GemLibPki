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
import static de.gematik.pki.gemlibpki.tsl.TslSignerTest.SIGNER_PATH_ECC;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getFilePathFromResources;
import static de.gematik.pki.gemlibpki.utils.TestUtils.readP12;
import static de.gematik.pki.gemlibpki.utils.XmlCompare.documentsAreEqual;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.tsl.TslConverter.DocToBytesOption;
import de.gematik.pki.gemlibpki.tsl.TslSigner.TslSignerBuilder;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.w3c.dom.Document;

class TslConverterTest {

  private static final Path TSL_PATH = getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT);

  @Test
  void tslToDoc() {
    final TrustStatusListType tsl = TslReader.getTsl(TSL_PATH);
    assertThat(documentsAreEqual(TslConverter.tslToDoc(tsl), TSL_PATH)).isTrue();
  }

  @Test
  void bytesToDoc() {
    final byte[] tslBytes = GemLibPkiUtils.readContent(TSL_PATH);
    assertThat(documentsAreEqual(TslConverter.bytesToDoc(tslBytes), TSL_PATH)).isTrue();
  }

  @Test
  void docToBytes() {
    final Document tslDoc = TslReader.getTslAsDoc(TSL_PATH);
    assertThat(documentsAreEqual(TslConverter.docToBytes(tslDoc), TSL_PATH)).isTrue();
  }

  @ParameterizedTest
  @EnumSource(value = DocToBytesOption.class)
  void docToBytesWithDocToBytesOption(final DocToBytesOption docToBytesOption) {
    final Document tslDoc = TslReader.getTslAsDoc(TSL_PATH);
    final byte[] tslBytes = TslConverter.docToBytes(tslDoc, docToBytesOption);
    assertThat(documentsAreEqual(tslBytes, TSL_PATH)).isTrue();

    // TODO we also should test if formatting was applied
  }

  @Test
  void docToBytesPrettyPrint() {
    final String xmlOneLine =
        "<note><to>email1</to><from>email2</from><heading>Reminder</heading><body>Gematik!</body></note>";
    final String xmlPrettyPrintExpected =
        """
            <note>
                <to>email1</to>
                <from>email2</from>
                <heading>Reminder</heading>
                <body>Gematik!</body>
            </note>
            """;
    assertThat(xmlOneLine).isNotEqualTo(xmlPrettyPrintExpected);

    final Document xmlDoc = TslConverter.bytesToDoc(xmlOneLine.getBytes(StandardCharsets.UTF_8));
    final byte[] xmlPrettyPrintBytes =
        TslConverter.docToBytes(xmlDoc, DocToBytesOption.PRETTY_PRINT);

    String xmlPrettyPrint = new String(xmlPrettyPrintBytes, StandardCharsets.UTF_8);
    xmlPrettyPrint = xmlPrettyPrint.replace("\r\n", "\n");

    assertThat(xmlPrettyPrint).isEqualTo(xmlPrettyPrintExpected);
  }

  @Test
  void docToBytesPrettyPrintAndSign() {

    final TslSignerBuilder tslSignerBuilder = TslSigner.builder();
    final P12Container signerEcc = readP12(SIGNER_PATH_ECC);

    final TrustStatusListType tsl = TestUtils.getTsl(FILE_NAME_TSL_ECC_DEFAULT);

    final Document tslDoc = TslConverter.tslToDoc(tsl);
    final byte[] tslBytes = TslConverter.docToBytes(tslDoc);

    final String indentationIndicator = "\n ";
    assertThat(
            StringUtils.countMatches(
                new String(tslBytes, StandardCharsets.UTF_8), indentationIndicator))
        .isZero();

    tslSignerBuilder.tslToSign(tslDoc).tslSignerP12(signerEcc).build().sign();

    final byte[] signedTslBytes = TslConverter.docToBytes(tslDoc);

    // NOTE: sing() adds the signature element with few line breaks  (that are not pretty printed),
    // the original xml remains as is, in this case - a single line
    assertThat(
            StringUtils.countMatches(
                    new String(signedTslBytes, StandardCharsets.UTF_8), indentationIndicator)
                < 100)
        .isTrue();

    final Document tslDoc2 = TslConverter.bytesToDoc(tslBytes);

    final byte[] tslBytesPrettyPrinted =
        TslConverter.docToBytes(tslDoc2, DocToBytesOption.PRETTY_PRINT);
    final Document tslDocPrettyPrinted = TslConverter.bytesToDoc(tslBytesPrettyPrinted);
    tslSignerBuilder.tslToSign(tslDocPrettyPrinted).tslSignerP12(signerEcc).build().sign();

    final byte[] signedAndPrettyPrintedTslBytes = TslConverter.docToBytes(tslDocPrettyPrinted);

    int countIndentationIndicator =
        StringUtils.countMatches(
            new String(tslBytesPrettyPrinted, StandardCharsets.UTF_8), indentationIndicator);
    assertThat(countIndentationIndicator > 5000).isTrue();

    countIndentationIndicator =
        StringUtils.countMatches(
            new String(signedAndPrettyPrintedTslBytes, StandardCharsets.UTF_8),
            indentationIndicator);
    assertThat(countIndentationIndicator > 5000).isTrue();
  }

  @Test
  void bytesToTsl() {
    final byte[] tslBytes = GemLibPkiUtils.readContent(TSL_PATH);
    assertThat(documentsAreEqual(TslConverter.bytesToTsl(tslBytes), TslReader.getTsl(TSL_PATH)))
        .isTrue();
  }

  @Test
  void nonNullTests() {
    assertThatThrownBy(() -> TslConverter.tslToDoc(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tsl is marked non-null but is null");
    assertThatThrownBy(() -> TslConverter.docToBytes(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tslDoc is marked non-null but is null");
  }
}
