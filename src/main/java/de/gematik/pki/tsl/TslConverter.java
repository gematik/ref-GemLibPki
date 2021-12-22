/*
 * Copyright (c) 2021 gematik GmbH
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

import static de.gematik.pki.tsl.TslHelper.createDocBuilder;
import static de.gematik.pki.tsl.TslHelper.createJaxbElement;
import static de.gematik.pki.tsl.TslHelper.createMarshaller;
import static de.gematik.pki.tsl.TslHelper.getTransformerFactory;
import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * Utility class for conversion of tsl objects in other structures
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TslConverter {

    public static final String ERROR_READING_TSL = "Error reading TSL";
    public static final String TSL_BYTES_NULL = "Input TSL ist null";

    /**
     * Converts a tsl to a DOM document type
     *
     * @param tsl The tsl to convert
     * @return The tsl as a DOM Document
     * @throws GemPkiException Exception thrown if tsl cannot be read
     */
    public static Optional<Document> tslToDoc(@NonNull final TrustStatusListType tsl) throws GemPkiException {
        try {
            final Document doc = createDocBuilder().newDocument();
            doc.setXmlStandalone(true);
            createMarshaller().marshal(createJaxbElement(tsl), doc);
            return Optional.of(doc);
        } catch (final JAXBException | ParserConfigurationException e) {
            throw new GemPkiException(ErrorCode.TSL_READ, "Conversion of TrustServiceStatusList to document failed.", e);
        }
    }

    /**
     * @param tslBytes A TSL as byte array
     * @return A TSL as Document
     * @throws GemPkiException on any conversion error
     */
    public static Optional<Document> bytesToDoc(final byte[] tslBytes) throws GemPkiException {
        Objects.requireNonNull(tslBytes, TSL_BYTES_NULL);
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(tslBytes)) {
            final Document document = createDocBuilder().parse(bais);
            document.setXmlStandalone(true);
            document.normalize();
            return Optional.of(document);
        } catch (final ParserConfigurationException | SAXException | IOException e) {
            throw new GemPkiException(ErrorCode.TSL_READ, ERROR_READING_TSL, e);
        }
    }

    /**
     * @param tslDoc A TSL as Document
     * @return A TSL as byte array
     * @throws GemPkiException on any conversion error
     */
    public static Optional<byte[]> docToBytes(@NonNull final Document tslDoc) throws GemPkiException {
        final TransformerFactory tf = getTransformerFactory();
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            tf.newTransformer().transform(new DOMSource(tslDoc), new StreamResult(baos));
            return Optional.of(baos.toByteArray());
        } catch (final TransformerException | IOException e) {
            throw new GemPkiException(ErrorCode.TSL_READ, ERROR_READING_TSL, e);
        }
    }

    /**
     * @param tslBytes A TSL as byte array
     * @return A TSL as TrustStatusListType
     * @throws GemPkiException on any conversion error
     */
    public static Optional<TrustStatusListType> bytesToTsl(final byte[] tslBytes) throws GemPkiException {
        Objects.requireNonNull(tslBytes, TSL_BYTES_NULL);
        final JAXBContext jaxbContext;
        try {
            jaxbContext = JAXBContext
                .newInstance(TrustStatusListType.class);
            final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            final JAXBElement<TrustStatusListType> jaxbElement =
                unmarshaller.unmarshal(bytesToDoc(tslBytes).orElseThrow().getFirstChild(), TrustStatusListType.class);
            return Optional.of(jaxbElement.getValue());
        } catch (final JAXBException e) {
            throw new GemPkiException(ErrorCode.TSL_READ, ERROR_READING_TSL, e);
        }
    }

}
