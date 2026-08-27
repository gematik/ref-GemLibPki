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

import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** Class to provide {@link TspService}. */
@RequiredArgsConstructor
public class TslInformationProvider {

  private final TrustStatusListType tslUnsigned;

  /**
   * Get list of {@link TspService} to given service type identifiers.
   *
   * @param stiFilterList list with ServiceTypeIdentifiers to filter on
   * @return list with {@link TspService}
   */
  public List<TspService> getFilteredTspServices(@NonNull final List<String> stiFilterList) {
    return tslUnsigned.getTrustServiceProviderList().getTrustServiceProvider().stream()
        .flatMap(
            tspType -> {
              if (tspType.getTSPServices() == null
                  || tspType.getTSPServices().getTSPService() == null) {
                return java.util.stream.Stream
                    .<eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType>empty();
              }
              return tspType.getTSPServices().getTSPService().stream();
            })
        .filter(
            tspServiceType -> {
              if (tspServiceType == null || tspServiceType.getServiceInformation() == null) {
                return false;
              }
              final String sti = tspServiceType.getServiceInformation().getServiceTypeIdentifier();
              return sti != null && stiFilterList.contains(sti);
            })
        .map(TspService::new)
        .toList();
  }

  /**
   * Get list of all {@link TspService}.
   *
   * @return list with {@link TspService}
   */
  public List<TspService> getTspServices() {
    return tslUnsigned.getTrustServiceProviderList().getTrustServiceProvider().stream()
        .flatMap(
            f -> {
              if (f.getTSPServices() == null || f.getTSPServices().getTSPService() == null) {
                return java.util.stream.Stream
                    .<eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType>empty();
              }
              return f.getTSPServices().getTSPService().stream();
            })
        .filter(s -> s != null && s.getServiceInformation() != null)
        .map(TspService::new)
        .toList();
  }

  /**
   * @param tsp trust service provider of the TSL to get services from
   * @param stiFilterList list of URIs with service type identifiers to look for
   * @return list of trusted services
   */
  public List<TspService> getTspServicesForTsp(
      @NonNull final String tsp, @NonNull final List<String> stiFilterList) {
    final List<TSPType> tspTypes =
        tslUnsigned.getTrustServiceProviderList().getTrustServiceProvider().stream()
            .filter(
                tspType -> {
                  final String tspName =
                      tspType.getTSPInformation().getTSPName().getName().getFirst().getValue();
                  return tsp.equals(tspName);
                })
            .toList();

    return tspTypes.stream()
        .flatMap(
            f -> {
              if (f.getTSPServices() == null || f.getTSPServices().getTSPService() == null) {
                return java.util.stream.Stream
                    .<eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType>empty();
              }
              return f.getTSPServices().getTSPService().stream();
            })
        .filter(c -> c != null && c.getServiceInformation() != null)
        .filter(
            c -> {
              final String sti = c.getServiceInformation().getServiceTypeIdentifier();
              return sti != null && stiFilterList.contains(sti);
            })
        .map(TspService::new)
        .toList();
  }
}
