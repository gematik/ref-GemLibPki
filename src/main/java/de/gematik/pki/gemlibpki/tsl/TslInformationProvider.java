/*
 * Copyright (c) 2022 gematik GmbH
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

import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;

/** Class to provide {@link TspService}. */
@RequiredArgsConstructor
public class TslInformationProvider {

  private final TrustStatusListType trustServiceStatusList;

  /**
   * Get list of {@link TspService} to given service type identifiers.
   *
   * @param stiFilterList list with ServiceTypeIdentifiers to filter on
   * @return list with {@link TspService}
   */
  public List<TspService> getFilteredTspServices(final List<String> stiFilterList) {

    return trustServiceStatusList.getTrustServiceProviderList().getTrustServiceProvider().stream()
        .flatMap(
            f ->
                f.getTSPServices().getTSPService().stream()
                    .filter(
                        c ->
                            stiFilterList.contains(
                                c.getServiceInformation().getServiceTypeIdentifier())))
        .map(TspService::new)
        .collect(Collectors.toList());
  }

  /**
   * Get list of all {@link TspService}.
   *
   * @return list with {@link TspService}
   */
  public List<TspService> getTspServices() {
    return trustServiceStatusList.getTrustServiceProviderList().getTrustServiceProvider().stream()
        .flatMap(f -> f.getTSPServices().getTSPService().stream())
        .map(TspService::new)
        .collect(Collectors.toList());
  }

  public List<TspService> getTspServicesForTsp(final String tsp, final List<String> stiFilterList) {
    final List<TSPType> tspTypes =
        trustServiceStatusList.getTrustServiceProviderList().getTrustServiceProvider().stream()
            .filter(
                c -> tsp.contains(c.getTSPInformation().getTSPName().getName().get(0).getValue()))
            .collect(Collectors.toList());

    return tspTypes.stream()
        .flatMap(f -> f.getTSPServices().getTSPService().stream())
        .filter(c -> stiFilterList.contains(c.getServiceInformation().getServiceTypeIdentifier()))
        .map(TspService::new)
        .collect(Collectors.toList());
  }
}
