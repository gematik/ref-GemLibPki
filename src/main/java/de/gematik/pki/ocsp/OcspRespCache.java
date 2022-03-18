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

package de.gematik.pki.ocsp;

import java.math.BigInteger;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Class to support ocsp a responder cache (to implement ocsp grace periods) old entries of the cache are deleted when a cached entry is requested
 */
@Slf4j
public class OcspRespCache {

    private int ocspGracePeriodSeconds;
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
     * @param x509EeCertSerialNumber big integer of the certificate serial number to ask the response for
     * @return optional of ocsp response
     */
    public synchronized Optional<OCSPResp> getResponse(final BigInteger x509EeCertSerialNumber) {
        deleteExpiredResponses();
        return Optional.ofNullable(cache.get(x509EeCertSerialNumber));
    }

    /**
     * Writing ocsp response to the cache
     *
     * @param x509EeCertSerialNumber big integer of serial of the certificate
     * @param ocspResp               ocsp response
     */
    public void saveResponse(final BigInteger x509EeCertSerialNumber, final OCSPResp ocspResp) {
        cache.put(x509EeCertSerialNumber, ocspResp);
    }

    /**
     * Setter for a new ocsp grace period
     *
     * @param ocspGracePeriodSeconds the new grace period in seconds
     */
    public void setOcspGracePeriodSeconds(final int ocspGracePeriodSeconds) {
        this.ocspGracePeriodSeconds = ocspGracePeriodSeconds;
    }

    /**
     * Getter for the actual ocsp grace period
     *
     * @return actual grace period in seconds
     */
    public int getOcspGracePeriodSeconds() {
        return ocspGracePeriodSeconds;
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
        log.warn("Deleting cached OCSP responses is not implemented yet. Cache size:{}", cache.size());
        //TODO get current time, compare ... ocspGracePeriodSeconds and delete all expired responses (responses with status revoked remain)
    }
}
