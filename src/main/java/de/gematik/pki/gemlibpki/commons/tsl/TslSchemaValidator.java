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

import static de.gematik.pki.gemlibpki.commons.utils.ResourceReader.getUrlFromResources;
import static javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.net.URL;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class TslSchemaValidator {

  static void validateWellFormedXml(
      final byte @NonNull [] tslBytes, @NonNull final String productType, final ErrorCode errorCode)
      throws GemPkiException {
    try {
      TslConverter.bytesToDoc(tslBytes);
    } catch (final GemPkiRuntimeException e) {
      if (e.getCause() instanceof SAXException) {
        throw new GemPkiException(productType, errorCode);
      }
      throw e;
    }
  }

  static Validator getValidator(
      @NonNull final String scheme, @NonNull final Class<?> resourceClass) {
    final SchemaFactory schemaFactory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI); // NOSONAR
    final URL schemaUrl = getUrlFromResources(scheme, resourceClass);
    final Schema compiledSchema;
    try {
      compiledSchema = schemaFactory.newSchema(schemaUrl);
    } catch (final SAXException e) {
      throw new GemPkiRuntimeException("Error during parsing of schema file.", e);
    }

    return compiledSchema.newValidator();
  }

  static void validateAgainstXsd(
      @NonNull final Validator validator,
      final byte @NonNull [] tslBytes,
      @NonNull final String productType,
      final ErrorCode errorCode)
      throws GemPkiException {

    final Document tslToCheckDoc = TslConverter.bytesToDoc(tslBytes);
    try {
      validator.validate(new DOMSource(tslToCheckDoc));
    } catch (final SAXException e) {
      throw new GemPkiException(productType, errorCode, e);
    } catch (final IOException e) {
      throw new GemPkiRuntimeException("Error reading schema file.", e);
    }
  }
}
