/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 /*
  * mod_cspnonce.c: Generate a cryptographically secure base64 encoded CSP nonce.
  *
  * Original author: wyDay, LLC <support@wyday.com>
  *
  * https://github.com/wyattoday/mod_cspnonce
  */

#include "apr_general.h"    /* for apr_generate_random_bytes */
#include "apr_base64.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"  /* for ap_hook_post_read_request */


typedef unsigned char byte;

const char* GenSecureCSPNonce(const request_rec* r)
{
    // Generate 9 random bytes. Any multiple of 3 will work
    // well because the base64 string generated will not require
    // padding (i.e. useless characters).
    // If you modify this number you'll need to modify the string length
    // and null terminator below.
    byte random_bytes[9];

    apr_generate_random_bytes(random_bytes, sizeof(random_bytes));

    char* cspNonce;

    // Allocate 13 bytes for the base64 string + NULL.
    // Base64 uses 4 ascii characters to encode 24-bits (3 bytes) of data
    // Thus we need 12 characters + 1 NULL char to store 9 bytes of random data.
    cspNonce = (char*)apr_palloc(r->pool, 13);

    // null terminate string
    cspNonce[12] = '\0';

    apr_base64_encode(cspNonce, (const char*)random_bytes, sizeof(random_bytes));

    return cspNonce;
}

static int set_cspnonce(request_rec* r)
{
    const char* id = NULL;

    /* copy the CSP_NONCE if this is an internal redirect (we're never
     * actually called for sub requests, so we don't need to test for
     * them) */
    if (r->prev) {
        id = apr_table_get(r->subprocess_env, "REDIRECT_CSP_NONCE");
    }

    if (!id) {
        id = GenSecureCSPNonce(r);
    }

    /* set the environment variable */
    apr_table_setn(r->subprocess_env, "CSP_NONCE", id);

    return DECLINED;
}

static void register_hooks(apr_pool_t* p)
{
    ap_hook_post_read_request(set_cspnonce, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(cspnonce) = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
