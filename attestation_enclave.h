#ifndef ATTESTATION_ENCLAVE_H
#define ATTESTATION_ENCLAVE_H

#include <sm.h>

typedef struct attestation_enclave_io_t {
  enclave_t * expected_message_sender;
} attestation_enclave_io_t;
attestation_enclave_io_t attestation_enclave_io;

void attestation_enclave_entry();

#endif // ATTESTATION_ENCLAVE_H
