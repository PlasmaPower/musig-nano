#include <stdint.h>
#include <stddef.h>

#ifndef MUSIG_BANANO_INTERFACE_H
#define MUSIG_BANANO_INTERFACE_H

/** This indicates a problem within this library, e.g. it failed to initialize a secure random number generator. */
#define MUSIG_INTERNAL_ERROR 1
/** This indicates a problem with a function's parameters, e.g. an incorrect number of responses were supplied. */
#define MUSIG_PARAMS_ERROR 2
/** This indicates a problem with a parameter from a peer, e.g. a public key was invalid. */
#define MUSIG_PEER_ERROR 3

/** Used to specify that the private key shouldn't be hashed, and should instead be interpreted as a scalar. */
#define MUSIG_FLAG_SCALAR_KEY (1 << 0)

/**
 * Aggregate public keys into a single public key.
 * \param pubkeys An array of pointers to public keys. Each public key should be 32 bytes long (in compressed edwards y format). Order does not matter, as the list will be internally sorted. Duplicates will also be internally removed.
 * \param count The amount of pubkeys supplied.
 * \param error_out If an error occurs, this will be set to the error code.
 * \param aggregated_pubkey_out The 32 byte output for the aggregated public key (compressed edwards y format).
 */
void musig_aggregate_public_keys(uint8_t const * const * pubkeys, size_t count, uint8_t * error_out, uint8_t * aggregated_pubkey_out);

typedef struct stage0 stage0;
typedef struct stage1 stage1;
typedef struct stage2 stage2;

/**
 * Start a MuSig session.
 * \param error_out If an error occurs, this will be set to the error code and nullptr will be returned.
 * \param publish_out A 32 byte output that should be published to other participants (used in the next stage).
 * \returns A stage0 struct representing the state of the MuSig session.
 */
stage0 * musig_stage0(uint8_t * error_out, uint8_t * publish_out);
/**
 * Progress a MuSig session from stage 0 to stage 1.
 * \param stage0 The previous state of the MuSig session. This frees the struct, so do *not* call this with the same struct multiple times or call musig_free_stage0 with the stage in addition to this function.
 * \param private_key The private key of the participant.
 * \param pubkeys An array of pointers to public keys. Each public key should be 32 bytes long (in compressed edwards y format). Order does not matter, as the list will be internally sorted. It may optionally contain this participant's public key. Since duplicates are internally removed, having two participants in a MuSig session with the same key will cause the session not to work.
 * \param pubkeys_count The amount of pubkeys supplied.
 * \param flags Documented above, flags can change behavior in various ways.
 * \param message The message to sign. For Banano, this is a block hash.
 * \param message_length The length of the message.
 * \param responses An array of pointers to 32 byte messages published in stage0. This may optionally include our own message and/or duplicates. It may be in any order.
 * \param responses_count The number of responses in the responses array.
 * \param error_out If an error occurs, this will be set to the error code and nullptr will be returned. If any error but MUSIG_INTERNAL_ERROR is returned, stage0 will remain intact.
 * \param aggregated_pubkey_out The 32 byte output for the aggregated public key (compressed edwards y format) or optionally null.
 * \param publish_out A 32 byte output that should be published to other participants (used in the next stage).
 * \returns A stage1 struct representing the state of the MuSig session.
 */
stage1 * musig_stage1(
    stage0 * stage0,
    uint8_t const * private_key,
    uint8_t const * const * pubkeys,
    size_t pubkeys_count,
    uint32_t flags,
    uint8_t const * message,
    size_t message_length,
    uint8_t const * const * responses,
    size_t responses_count,
    uint8_t * error_out,
    uint8_t * aggregated_pubkey_out,
    uint8_t * publish_out
);
/**
 * Progress a MuSig session from stage 1 to stage 2.
 * \param stage1 The previous state of the MuSig session. This frees the struct, so do *not* call this with the same struct multiple times or call musig_free_stage1 with the stage in addition to this function.
 * \param responses An array of pointers to 32 byte messages published in stage1. This may optionally include our own message and/or duplicates. It may be in any order.
 * \param responses_count The number of responses in the responses array.
 * \param error_out If an error occurs, this will be set to the error code and nullptr will be returned. If any error but MUSIG_INTERNAL_ERROR is returned, stage1 will remain intact.
 * \param publish_out A 32 byte output that should be published to other participants (used in the next stage).
 * \returns A stage2 struct representing the state of the MuSig session.
 */
stage2 * musig_stage2(stage1 * stage1, uint8_t const * const * responses, size_t responses_count, uint8_t * error_out, uint8_t * publish_out);
/**
 * Finishes a musig session, producing the signature.
 * \param stage2 The previous state of the MuSig session. This frees the struct, so do *not* call this with the same struct multiple times or call musig_free_stage2 with the stage in addition to this function.
 * \param responses An array of pointers to 32 byte messages published in stage2. This may optionally include our own message and/or duplicates. It may be in any order.
 * \param responses_count The number of responses in the responses array.
 * \param error_out If an error occurs, this will be set to the error code. If any error but MUSIG_INTERNAL_ERROR is returned, stage2 will remain intact.
 * \param signature_out A 64 byte output that will be filled with the signature.
 */
void musig_stage3(stage2 * stage2, uint8_t const * const * responses, size_t responses_count, uint8_t * error_out, uint8_t * signature_out);

/**
 * Frees a stage0 struct. Since musig_stage1 frees its stage0 input, this should only be used if the MuSig session is aborted.
 */
void musig_free_stage0(stage0 * stage0);
/**
 * Frees a stage1 struct. Since musig_stage2 frees its stage1 input, this should only be used if the MuSig session is aborted.
 */
void musig_free_stage1(stage1 * stage1);
/**
 * Frees a stage2 struct. Since musig_stage3 frees its stage2 input, this should only be used if the MuSig session is aborted.
 * This can also be used if this participant does not need the signature (another participant or the message passer can derive the signature and publish it).
 */
void musig_free_stage2(stage2 * stage2);

/**
 * Derives a MuSig signature from a session's messages. This is useful if a message passer server is responsible for publishing the signature.
 * \param aggregated_pubkey The aggregated public key for the MuSig session. This can be derived with musig_aggregate_public_keys.
 * \param message The message that is being signed. For Banano, this is a block hash.
 * \param message_length The length of the message.
 * \param stage1_messages An array of pointers to 32 byte messages produced in stage 1.
 * \param stage1_messages_count The number of messages produced in stage 1.
 * \param stage2_messages An array of pointers to 32 byte messages produced in stage 2.
 * \param stage2_messages_count The number of messages produced in stage 2. This should probably be the same as stage1_messages_count but it's here for safety.
 * \param error_out If an error occurs, this will be set to the error code and signature_out will remain unchanged.
 * \param signature_out A 64 byte output that will be filled with the signature.
 */
void musig_observe(uint8_t const * aggregated_pubkey, uint8_t const * message, size_t message_length, uint8_t const * const * stage1_messages, size_t stage1_messages_count, uint8_t const * const * stage2_messages, size_t stage2_messages_count, uint8_t * error_out, uint8_t * signature_out);

#endif // MUSIG_BANANO_INTERFACE_H
