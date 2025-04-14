/*
 * Copyright 2025, gematik GmbH
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
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.tsl;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/** Utility class for conversion of tsl objects in other structures */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslConverter {

  public static final String XSLT_PRETTY_PRINT =
      """
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output omit-xml-declaration="yes" indent="yes"/>
        <xsl:template match="node()|@*">
          <xsl:copy>
            <xsl:apply-templates select="node()|@*"/>
          </xsl:copy>
        </xsl:template>
      </xsl:stylesheet>
      """;

  public static final String XSLT_NO_LINE_BREAKS =
      """
      <?xml version="1.0" encoding="UTF-8"?>
      <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:strip-space elements="*"/>
          <!-- this is called an identity template -->
          <xsl:template match="node()|@*">
              <xsl:copy>
                  <xsl:apply-templates select="node()|@*"/>
              </xsl:copy>
          </xsl:template>
      </xsl:stylesheet>
      """;

  public static final String ERROR_READING_TSL = "Error reading TSL.";

  /**
   * Converts a tslUnsigned to a DOM document type
   *
   * @param tslUnsigned The tslUnsigned to convert
   * @return The tslUnsigned as a DOM Document
   */
  public static Document tslToDocUnsigned(@NonNull final TrustStatusListType tslUnsigned) {
    try {
      final Document doc = TslUtils.createDocBuilder().newDocument();
      doc.setXmlStandalone(true);

      final JAXBElement<TrustStatusListType> jaxbElement = TslUtils.createJaxbElement(tslUnsigned);
      TslUtils.createMarshaller().marshal(jaxbElement, doc);

      return doc;
    } catch (final JAXBException | ParserConfigurationException e) {
      throw new GemPkiRuntimeException(
          "Error converting TrustServiceStatusList to Document type.", e);
    }
  }

  /**
   * @param tslBytes A TSL as byte array
   * @return A TSL as Document
   */
  public static Document bytesToDoc(final byte @NonNull [] tslBytes) {
    try (final ByteArrayInputStream bais = new ByteArrayInputStream(tslBytes)) {
      final Document document = TslUtils.createDocBuilder().parse(bais);
      document.setXmlStandalone(true);
      return document;
    } catch (final ParserConfigurationException | SAXException | IOException e) {
      throw new GemPkiRuntimeException(ERROR_READING_TSL, e);
    }
  }

  public enum DocToBytesOption {

    /** no formatting is performed */
    UNDEFINED,

    /**
     * pretty print XSLT is applied; be aware that this can invalidate signature of a signed
     * document
     */
    PRETTY_PRINT,

    /**
     * applies XSLT that convert XML to its single line representation; be aware that this can
     * invalidate signature of a signed document
     */
    NO_LINE_BREAKS,

    /**
     * applies XSLT that convert XML to its single line representation; be aware that this can
     * invalidate signature of a signed document
     */
    RESET
  }

  public static byte[] docToBytes(@NonNull final Document tslDoc) {
    return docToBytes(tslDoc, DocToBytesOption.UNDEFINED);
  }

  /**
   * @param tslDoc A TSL as Document
   * @param docToBytesOption a {@link DocToBytesOption}
   * @return A TSL as byte array
   */
  public static byte[] docToBytes(
      @NonNull Document tslDoc, final DocToBytesOption docToBytesOption) {

    if ((docToBytesOption != DocToBytesOption.RESET)
        && (docToBytesOption != DocToBytesOption.UNDEFINED)) {
      // we have to reset xml formatting before applying transformations
      final byte[] tslBytes = docToBytes(tslDoc, DocToBytesOption.RESET);
      tslDoc = TslConverter.bytesToDoc(tslBytes);
    }

    final TransformerFactory transformerFactory = TslUtils.getTransformerFactory();
    try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

      final Transformer transformer;
      switch (docToBytesOption) {
        case NO_LINE_BREAKS, RESET -> transformer =
            transformerFactory.newTransformer(
                new StreamSource(new StringReader(XSLT_NO_LINE_BREAKS)));

        case PRETTY_PRINT -> transformer =
            transformerFactory.newTransformer(
                new StreamSource(new StringReader(XSLT_PRETTY_PRINT)));

        default -> transformer = transformerFactory.newTransformer();
      }

      transformer.transform(new DOMSource(tslDoc), new StreamResult(baos));
      return baos.toByteArray();
    } catch (final TransformerException | IOException e) {
      throw new GemPkiRuntimeException(ERROR_READING_TSL, e);
    }
  }

  /**
   * @param tslBytes A TSL as byte array
   * @return A TSL as TrustStatusListType with invalid/broken signature
   */
  public static TrustStatusListType bytesToTslUnsigned(final byte @NonNull [] tslBytes) {
    try {
      final Unmarshaller unmarshaller = TslUtils.createUnmarshaller();
      final Node node = bytesToDoc(tslBytes).getFirstChild();

      final JAXBElement<TrustStatusListType> jaxbElement =
          unmarshaller.unmarshal(node, TrustStatusListType.class);

      return jaxbElement.getValue();
    } catch (final JAXBException e) {
      throw new GemPkiRuntimeException(ERROR_READING_TSL, e);
    }
  }

  /**
   * Converts a tsl to a byte array
   *
   * @param tsl The tsl to convert
   * @return A TSL as byte array
   */
  public static byte[] tslUnsignedToBytes(@NonNull final TrustStatusListType tsl) {
    return docToBytes(tslToDocUnsigned(tsl));
  }
}
