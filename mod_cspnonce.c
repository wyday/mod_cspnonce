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
 * https://github.com/wyday/mod_cspnonce
*/

#include "apr_base64.h"
#include "apr_random.h"

#include "httpd.h"
#include "http_log.h"
#include "http_config.h"
#include "http_protocol.h" /* for ap_hook_post_read_request */

// Generate 18 random bytes (144-bits). Any multiple of 3 will work
// well because the base64 string generated will not require
// padding (i.e. useless characters).
// If you modify this number you'll need to modify the string length
// and null terminator below.

// This number is based on the seemlingly made-up number used in
// the W3C "webappsec-csp" document. It seems made-up (i.e. a number
// not based on either theoretical or real-world testing) because
// 128-bits cannot be divided evenly into a base64-encoded string.
// But, whatever, I'll let someone else fight that battle.
// Here is the nonsense source: https://w3c.github.io/webappsec-csp/#security-nonces

#ifndef CSPNONCE_RANDOM_LEN 
#define CSPNONCE_RANDOM_LEN (18)
#endif

#ifdef _WIN32
#    include <Windows.h>
#    include <bcrypt.h>
#    include <stdio.h>

#    pragma comment(lib, "Bcrypt")
#else
#    include <stdlib.h>
#    ifndef __APPLE__
#        include <time.h>
#    endif
#endif

typedef unsigned char byte;

typedef struct {
    apr_random_t * rnd_state;
} csp_config;

module cspnonce;

/*
* Generates a 12-character string (13 bytes to account for null).
* It's random and base64 encoded.
*
* On error NULL is returned.
*/
const char * GenSecureCSPNonce(const request_rec * r)
{
    csp_config * cfg = ap_get_module_config(r->server->module_config, &cspnonce);
    byte random_bytes[CSPNONCE_RANDOM_LEN];

    apr_status_t status;
    if ((status = apr_random_secure_bytes(cfg->rnd_state, random_bytes, CSPNONCE_RANDOM_LEN)) != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "mod_csp: generation failed");
	return NULL;
    }

    char * cspNonce;
    // Avoid the use of sizeof; to not get 'rounded up' by a compiler.
    cspNonce = (char *)apr_palloc(r->pool, apr_base64_encode_len(CSPNONCE_RANDOM_LEN));

    // null terminate string
    cspNonce[24] = '\0';

    apr_base64_encode(cspNonce, (const char *)random_bytes, CSPNONCE_RANDOM_LEN);

    return cspNonce;
}

static int set_cspnonce(request_rec * r)
{
    const char * id = NULL;

    /* copy the CSP_NONCE if this is an internal redirect (we're never
     * actually called for sub requests, so we don't need to test for
     * them) */
    if (r->prev)
        id = apr_table_get(r->subprocess_env, "REDIRECT_CSP_NONCE");

    if (id == NULL)
        id = GenSecureCSPNonce(r);

    /* set the environment variable */
    if (id != NULL)
        apr_table_setn(r->subprocess_env, "CSP_NONCE", id);

    return DECLINED;
}

static void * create_srv_config(apr_pool_t *p, server_rec *s) {
     return apr_pcalloc(p, sizeof(csp_config));
}

static void init_rnd(apr_pool_t *p, server_rec *s) {
    csp_config * cfg = (csp_config *)ap_get_module_config(s->module_config, &cspnonce);
    if (NULL == (cfg->rnd_state = apr_random_standard_new(p))) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "mod_csp: random generator init failed - INSECURE");
    }
}

static void register_hooks(apr_pool_t * p)
{
    ap_hook_post_read_request(set_cspnonce, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(init_rnd, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(cspnonce) = {
    STANDARD20_MODULE_STUFF,
    NULL,             /* dir config creater */
    NULL,             /* dir merger --- default is to override */
    create_srv_config,/* server config */
    NULL,             /* merge server configs */
    NULL,             /* command apr_table_t */
    register_hooks    /* register hooks */
};
