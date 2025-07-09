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

package de.gematik.pki.gemlibpki.ocsp;

import static de.gematik.pki.gemlibpki.ocsp.OcspUtils.getBasicOcspResp;

import java.math.BigInteger;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Class to support ocsp a responder cache (to implement ocsp grace periods) old entries of the
 * cache are deleted when a cached entry is requested
 */
@Getter
@Slf4j
public class OcspRespCache {

  @Setter private int ocspGracePeriodSeconds;
  private final ConcurrentHashMap<BigInteger, OCSPResp> cache = new ConcurrentHashMap<>();

  /**
   * Constructor
   *
   * @param ocspGracePeriodSeconds of the ocsp grace period in seconds
   */
  public OcspRespCache(final int ocspGracePeriodSeconds) {
    this.ocspGracePeriodSeconds = ocspGracePeriodSeconds;
  }

  /**
   * Reading the response for a specific certificate
   *
   * @param certSerialNr big integer of the certificate serial number to ask the response for
   * @return optional of ocsp response
   */
  public synchronized Optional<OCSPResp> getResponse(@NonNull final BigInteger certSerialNr) {
    deleteExpiredResponses();
    return Optional.ofNullable(cache.get(certSerialNr));
  }

  /**
   * Writing ocsp response to the cache
   *
   * @param certSerialNr big integer of serial of the certificate
   * @param ocspResp ocsp response
   */
  public void saveResponse(
      @NonNull final BigInteger certSerialNr, @NonNull final OCSPResp ocspResp) {
    cache.put(certSerialNr, ocspResp);
  }

  /**
   * Getter for the number of entries in the cache
   *
   * @return the cache size
   */
  public int getSize() {
    return cache.size();
  }

  private void deleteExpiredResponses() {

    final ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

    final List<BigInteger> expired = new ArrayList<>();
    for (final Entry<BigInteger, OCSPResp> entry : cache.entrySet()) {
      final OCSPResp ocspResp = entry.getValue();

      final ZonedDateTime producedAt =
          ZonedDateTime.ofInstant(
              getBasicOcspResp(ocspResp).getProducedAt().toInstant(), ZoneOffset.UTC);

      final long age = ChronoUnit.SECONDS.between(producedAt, now);

      if (age > ocspGracePeriodSeconds) {
        expired.add(entry.getKey());
      }
    }
    expired.forEach(cache::remove);
  }
}
