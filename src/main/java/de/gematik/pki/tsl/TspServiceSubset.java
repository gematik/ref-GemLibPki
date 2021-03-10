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

import eu.europa.esig.jaxb.tsl.ExtensionType;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.Builder;
import lombok.Getter;

/**
 * Class containing a subset of a TspService referring explicitly one issuer certificate
 */
@Builder
@Getter
public class TspServiceSubset {

    private final X509Certificate x509IssuerCert;
    private final String serviceStatus;
    private final ZonedDateTime statusStartingTime;
    private final String serviceSupplyPoint;
    private final List<ExtensionType> extensions;
}
