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

import eu.europa.esig.jaxb.tsl.TSPServiceType;
import eu.europa.esig.jaxb.tsl.TrustStatusListType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
public class TSLInformationProvider {

    private static final String STI_PKC = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC";
    private static final String STI_OCSP = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP";
    private static final String STI_SRV_CERT_CHANGE = "http://uri.etsi.org/TrstSvc/Svctype/TSLServiceCertChange";
    private static final List<String> STI_DEFAULT_FILTER_LIST = Arrays.asList(STI_PKC, STI_OCSP, STI_SRV_CERT_CHANGE);

    private final TrustStatusListType trustStatusList;

    public List<TSPServiceType> getTspServices() {
        return getTspServices(STI_DEFAULT_FILTER_LIST);
    }

    public List<TSPServiceType> getTspServices(final List<String> stiFilterList) {

        final List<TSPServiceType> tspServiceList = new ArrayList<>();
        tspServiceList
            .addAll(trustStatusList.getTrustServiceProviderList().getTrustServiceProvider()
                .stream()
                .flatMap(f -> f.getTSPServices().getTSPService()
                    .stream()
                    .filter(c -> stiFilterList.contains(c.getServiceInformation().getServiceTypeIdentifier())))
                .collect(Collectors.toList()));
        return tspServiceList;
    }

}
