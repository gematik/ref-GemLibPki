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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_ECC_DEFAULT;
import static de.gematik.pki.gemlibpki.tsl.TslSignerTest.SIGNER_PATH_ECC;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getFilePathFromResources;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertXmlEqual;
import static de.gematik.pki.gemlibpki.utils.TestUtils.readP12;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TslConverter.DocToBytesOption;
import de.gematik.pki.gemlibpki.tsl.TslSigner.TslSignerBuilder;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import jakarta.xml.bind.JAXBException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.w3c.dom.Document;

class TslConverterTest {

  private static final Path TSL_PATH =
      getFilePathFromResources(FILE_NAME_TSL_ECC_DEFAULT, TslConverter.class);

  @Test
  void tslToDoc() {
    final TrustStatusListType tsl = TslReader.getTslUnsigned(TSL_PATH);
    assertXmlEqual(TslConverter.tslToDocUnsigned(tsl), TSL_PATH);
  }

  @Test
  void testTslToDocException() {

    final TrustStatusListType tsl = TslReader.getTslUnsigned(TSL_PATH);

    try (final MockedStatic<TslUtils> tslUtilsMockedStatic =
        Mockito.mockStatic(TslUtils.class, Mockito.CALLS_REAL_METHODS)) {

      tslUtilsMockedStatic.when(TslUtils::createMarshaller).thenThrow(new JAXBException("message"));

      assertThatThrownBy(() -> TslConverter.tslToDocUnsigned(tsl))
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage("Error converting TrustServiceStatusList to Document type.")
          .cause()
          .isInstanceOf(JAXBException.class);
    }
  }

  @Test
  void bytesToDoc() {
    final byte[] tslBytes = GemLibPkiUtils.readContent(TSL_PATH);
    assertXmlEqual(TslConverter.bytesToDoc(tslBytes), TSL_PATH);
  }

  @Test
  void docToBytes() {
    final Document tslDoc = TslReader.getTslAsDoc(TSL_PATH);
    assertXmlEqual(TslConverter.docToBytes(tslDoc), TSL_PATH);
  }

  @Test
  void docToBytesException() throws TransformerConfigurationException {

    final Document tslDoc = TslReader.getTslAsDoc(TSL_PATH);

    final TransformerFactory transformerFactoryMock = Mockito.mock(TransformerFactory.class);
    Mockito.when(transformerFactoryMock.newTransformer())
        .thenThrow(new TransformerConfigurationException());

    try (final MockedStatic<TslUtils> tslUtilsMockedStatic =
        Mockito.mockStatic(TslUtils.class, Mockito.CALLS_REAL_METHODS)) {

      tslUtilsMockedStatic.when(TslUtils::getTransformerFactory).thenReturn(transformerFactoryMock);

      assertThatThrownBy(() -> TslConverter.docToBytes(tslDoc))
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage(TslConverter.ERROR_READING_TSL)
          .cause()
          .isInstanceOf(TransformerException.class);
    }
  }

  @ParameterizedTest
  @EnumSource(value = DocToBytesOption.class)
  void docToBytesWithDocToBytesOption(final DocToBytesOption docToBytesOption) {
    final Document tslDoc = TslReader.getTslAsDoc(TSL_PATH);
    final byte[] tslBytes = TslConverter.docToBytes(tslDoc, docToBytesOption);
    assertXmlEqual(tslBytes, TSL_PATH);
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

    final TrustStatusListType tslUnsigned = TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT);

    final Document tslDocUnsigned = TslConverter.tslToDocUnsigned(tslUnsigned);
    final byte[] tslBytesUnsigned = TslConverter.docToBytes(tslDocUnsigned);

    final String indentationIndicator = "\n ";
    assertThat(
            StringUtils.countMatches(
                new String(tslBytesUnsigned, StandardCharsets.UTF_8), indentationIndicator))
        .isZero();

    tslSignerBuilder.tslToSign(tslDocUnsigned).tslSignerP12(signerEcc).build().sign();

    final byte[] signedTslBytes = TslConverter.docToBytes(tslDocUnsigned);

    // NOTE: sing() adds the signature element with few line breaks  (that are not pretty printed),
    // the original xml remains as is, in this case - a single line
    assertThat(
            StringUtils.countMatches(
                new String(signedTslBytes, StandardCharsets.UTF_8), indentationIndicator))
        .isLessThan(100);

    final Document tslDoc2 = TslConverter.bytesToDoc(tslBytesUnsigned);

    final byte[] tslBytesPrettyPrintedUnsigned =
        TslConverter.docToBytes(tslDoc2, DocToBytesOption.PRETTY_PRINT);
    final Document tslDocPrettyPrinted = TslConverter.bytesToDoc(tslBytesPrettyPrintedUnsigned);
    tslSignerBuilder.tslToSign(tslDocPrettyPrinted).tslSignerP12(signerEcc).build().sign();

    final byte[] signedAndPrettyPrintedTslBytes = TslConverter.docToBytes(tslDocPrettyPrinted);

    final int nrOfMinIdents = 5000;

    int countIndentationIndicator =
        StringUtils.countMatches(
            new String(tslBytesPrettyPrintedUnsigned, StandardCharsets.UTF_8),
            indentationIndicator);
    assertThat(countIndentationIndicator).isGreaterThan(nrOfMinIdents);

    countIndentationIndicator =
        StringUtils.countMatches(
            new String(signedAndPrettyPrintedTslBytes, StandardCharsets.UTF_8),
            indentationIndicator);
    assertThat(countIndentationIndicator).isGreaterThan(nrOfMinIdents);
  }

  @Test
  void bytesToTsl() {
    final byte[] tslBytes = GemLibPkiUtils.readContent(TSL_PATH);
    assertXmlEqual(TslConverter.bytesToTslUnsigned(tslBytes), TslReader.getTslUnsigned(TSL_PATH));
  }

  @Test
  void bytesToTslException() {
    final byte[] tslBytes = GemLibPkiUtils.readContent(TSL_PATH);

    try (final MockedStatic<TslUtils> tslUtilsMockedStatic =
        Mockito.mockStatic(TslUtils.class, Mockito.CALLS_REAL_METHODS)) {

      tslUtilsMockedStatic
          .when(TslUtils::createUnmarshaller)
          .thenThrow(new JAXBException("message"));

      assertThatThrownBy(() -> TslConverter.bytesToTslUnsigned(tslBytes))
          .isInstanceOf(GemPkiRuntimeException.class)
          .hasMessage(TslConverter.ERROR_READING_TSL)
          .cause()
          .isInstanceOf(JAXBException.class);
    }
  }

  @Test
  void nonNullTests() {
    assertNonNullParameter(() -> TslConverter.tslToDocUnsigned(null), "tslUnsigned");
    assertNonNullParameter(() -> TslConverter.tslUnsignedToBytes(null), "tsl");
    assertNonNullParameter(() -> TslConverter.docToBytes(null), "tslDoc");
    assertNonNullParameter(() -> TslConverter.docToBytes(null, DocToBytesOption.RESET), "tslDoc");
    assertNonNullParameter(() -> TslConverter.bytesToDoc(null), "tslBytes");
    assertNonNullParameter(() -> TslConverter.bytesToTslUnsigned(null), "tslBytes");
  }
}
