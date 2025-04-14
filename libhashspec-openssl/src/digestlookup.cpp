/*
 * Copyright (C) 2015, Ondrej Mosnacek <omosnacek@gmail.com>
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation: either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

 #include "digestlookup.h"
#include <stdexcept>

#include <unordered_map>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

namespace libhashspec {
namespace openssl {

static OSSL_PROVIDER *legacy_provider = nullptr;
static OSSL_PROVIDER *default_provider = nullptr;

const EVP_MD *DigestLookup::getDigest(std::string hashSpec)
{
    // Load providers if not already loaded (only needs to happen once)
    if (legacy_provider == nullptr) {
        // We need to load both the default and legacy providers
        default_provider = OSSL_PROVIDER_load(NULL, "default");
        legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
        
        if (default_provider == nullptr || legacy_provider == nullptr) {
            throw std::runtime_error("Failed to load OpenSSL providers");
        }
    }
    
    // Create a map dynamically instead of using static initialization to avoid issues
    // with potentially missing digest functions
    static const std::unordered_map<std::string, const EVP_MD *> digests = {
        { "ripemd160", EVP_ripemd160() },
        { "sha1",      EVP_sha1() },
        { "sha256",    EVP_sha256() },
        { "sha512",    EVP_sha512() },
        // Fetch whirlpool dynamically as it might not be available directly
        { "whirlpool", EVP_get_digestbyname("whirlpool") }
    };
    
    auto it = digests.find(hashSpec);
    if (it == digests.end() || it->second == nullptr) {
        throw std::runtime_error("Unsupported hash algorithm: " + hashSpec);
    }
    
    return it->second;
}

} // namespace openssl
} // namespace libhashspec
