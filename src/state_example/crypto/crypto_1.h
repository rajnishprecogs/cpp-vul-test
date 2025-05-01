#ifndef CRYPTO_MODULE_1_H
#define CRYPTO_MODULE_1_H

#include <stdint.h>

#include "crypto_types.h"

extern uint8_t third_party_library_calc_hmac(const uint8_t *message, int len,
                                             const char *key, const char *nonce,
                                             uint8_t *hmac);

void crypto_init();

enum crypto_state crypto_get_state();

enum crypto_return_status crypto_set_key(crypto_key key);

enum crypto_return_status crypto_set_nonce(crypto_nonce nonce);

enum crypto_return_status crypto_calculate_hmac(const uint8_t *message, int len,
                                                crypto_hmac *hmac);

enum crypto_return_status crypto_verify_hmac(const uint8_t *message, int len,
                                             crypto_hmac *hmac);

#endif