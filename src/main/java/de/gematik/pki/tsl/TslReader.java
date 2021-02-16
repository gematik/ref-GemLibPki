/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.tsl;

import eu.europa.esig.jaxb.tsl.ObjectFactory;
import eu.europa.esig.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Objects;
import java.util.Optional;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TslReader {

    public Optional<TrustServiceStatusList> getTrustServiceStatusList(@NonNull final String tslFilename) {
        try (final InputStream inputStream = getClass().getClassLoader().getResourceAsStream(tslFilename)) {
            Objects.requireNonNull(inputStream);
            final JAXBContext jaxbContext = JAXBContext
                .newInstance(ObjectFactory.class, eu.europa.esig.jaxb.ecc.ObjectFactory.class);
            final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            final JAXBElement<TrustStatusListType> jaxbElement =
                (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(inputStream);
            return Optional.of(new TrustServiceStatusList(jaxbElement.getValue()));
        } catch (final JAXBException e) {
            throw new IllegalStateException("Unable to initialize or parse TSL: " + e, e);
        } catch (final IOException io) {
            throw new UncheckedIOException("Trouble reading TSL", io);
        }
    }
}
