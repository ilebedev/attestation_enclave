#include <ed25519/ed25519.h>
#include <sha3/sha3.h>
#include <stdio.h>

#include "attestation_enclave.h"
#include "enclave.h"

void attestation_enclave_entry() {
  uint8_t message[64];
  uint8_t sender_measurement[64];

  // See if there is a message waiting.
  if (OK != read_message(enclave_va_to_pa(sender_measurement), (enclave_va_to_pa(message)))) {
    // If not, prepare to receive one next time
    // Ask the OS which enclave will be sending an attesstation
    // Tell the platform to expect this enclave's message
    SM_ACCEPT_MESSAGE(attestation_enclave_io.sender);
  } else {
    // If an attestation request is pending,
    // 1). Fetch the platform's attestation key
    uint8_t attestation_key[64];
    SM_GET_ATTESTATION_KEY(enclave_va_to_pa(attestation_key));

    // 2). Sign sha3({sender, message}) with the platfomr's attestation key
    sha3_ctx_t hash_ctx;
    uint8_t scratchpad[64];
    uint8_t attestation[64];
    sha3_init(&hash_ctx, 64);
    sha3_update(&hash_ctx, sender_measurement, sizeof(sender_measurement));
    sha3_update(&hash_ctx, message, sizeof(message));
    sha3_final(scratchpad, &hash_ctx);
    ed25519_sign(attestation, scratchpad, sizeof(scratchpad), public_metadata.pk_sm, attestation_key);

    // 3). Send the signature back to the recipient
    SM_SEND_MESSAGE(attestation_enclave_io.sender, enclave_va_to_pa(attestation));
  }

  SM_EXIT_ENCLAVE(); // Stop
  __builtin_unreachable();
}

