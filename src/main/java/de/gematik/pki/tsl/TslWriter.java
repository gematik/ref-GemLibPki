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

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import javax.xml.bind.JAXBException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.w3c.dom.Document;

/**
 * Class to write a TSL from different types to file
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class TslWriter {

    public static final String STATUS_LIST_TO_FILE_FAILED = "Write of TrustServiceStatusList to file failed.";

    public static void write(@NonNull final TrustStatusListType tsl, @NonNull final Path tslFilePath) throws GemPkiException {
        try {
            TslHelper.createMarshaller().marshal(TslHelper.createJaxbElement(tsl), tslFilePath.toFile());
        } catch (final JAXBException e) {
            throw new GemPkiException(ErrorCode.UNKNOWN, STATUS_LIST_TO_FILE_FAILED, e);
        }
    }

    public static void write(@NonNull final Document tsl, @NonNull final Path filePath) throws GemPkiException {
        final TransformerFactory tf = TslHelper.getTransformerFactory();
        try {
            tf.newTransformer().transform(new DOMSource(tsl.getDocumentElement()), new StreamResult(filePath.toFile()));
        } catch (final TransformerException e) {
            throw new GemPkiException(ErrorCode.UNKNOWN, STATUS_LIST_TO_FILE_FAILED, e);
        }
    }
}
