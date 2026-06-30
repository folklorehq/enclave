#include <node_api.h>
#include <tinycbor/cbor.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define NSM_IOCTL_MAGIC 0x0A

struct nsm_ioctrl_args {
    const uint8_t *request;
    uint32_t       request_size;
    uint8_t       *response;
    uint32_t       response_size;
};

#define NSM_IOCTL     _IOWR(NSM_IOCTL_MAGIC, 0, struct nsm_ioctrl_args)
#define NSM_DEV       "/dev/nsm"
#define REQ_MAX_SIZE  512
#define RESP_MAX_SIZE (16 * 1024)

static int nsm_call(const uint8_t *req, uint32_t req_len,
                    uint8_t *resp, uint32_t *resp_len) {
    int fd = open(NSM_DEV, O_RDWR);
    if (fd < 0) return -errno;
    struct nsm_ioctrl_args args = {
        .request       = req,
        .request_size  = req_len,
        .response      = resp,
        .response_size = *resp_len,
    };
    int rc = ioctl(fd, NSM_IOCTL, &args);
    close(fd);
    if (rc < 0) return -errno;
    *resp_len = args.response_size;
    return 0;
}

// Both NSM responses are: map(1) text(key) map(1) text(key) bytes(payload).
static CborError parse_nested_bytes(const uint8_t *buf, size_t len,
                                    const uint8_t **out, size_t *out_len) {
    CborParser parser;
    CborValue root, outer_map, inner_map, value;
    CborError err;

    err = cbor_parser_init(buf, len, 0, &parser, &root);
    if (err) return err;
    err = cbor_value_enter_container(&root, &outer_map);
    if (err) return err;
    err = cbor_value_advance(&outer_map);
    if (err) return err;
    err = cbor_value_enter_container(&outer_map, &inner_map);
    if (err) return err;
    err = cbor_value_advance(&inner_map);
    if (err) return err;

    if (!cbor_value_is_byte_string(&inner_map)) return CborErrorIllegalType;
    err = cbor_value_get_string_length(&inner_map, out_len);
    if (err) return err;

    const uint8_t *chunk; size_t chunk_len;
    err = cbor_value_get_byte_string_chunk(&inner_map, (const void **)&chunk,
                                           &chunk_len, &value);
    if (err) return err;
    *out = chunk;
    return CborNoError;
}

static napi_value js_get_entropy(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    uint32_t n;
    napi_get_value_uint32(env, argv[0], &n);
    if (n == 0 || n > 256) {
        napi_throw_range_error(env, NULL, "entropy bytes must be 1-256");
        return NULL;
    }

    uint8_t req[REQ_MAX_SIZE];
    CborEncoder enc, map, arr;
    cbor_encoder_init(&enc, req, sizeof(req), 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_text_string(&map, "GetRandom", 9);
    cbor_encoder_create_array(&map, &arr, 0);
    cbor_encoder_close_container(&map, &arr);
    cbor_encoder_close_container(&enc, &map);
    uint32_t req_len = (uint32_t)cbor_encoder_get_buffer_size(&enc, req);

    uint8_t resp[RESP_MAX_SIZE];
    uint32_t resp_len = sizeof(resp);
    if (nsm_call(req, req_len, resp, &resp_len) < 0) {
        napi_throw_error(env, NULL, "NSM GetRandom ioctl failed");
        return NULL;
    }

    const uint8_t *entropy; size_t entropy_len;
    if (parse_nested_bytes(resp, resp_len, &entropy, &entropy_len) != CborNoError) {
        napi_throw_error(env, NULL, "unexpected NSM GetRandom response");
        return NULL;
    }
    if (entropy_len < n) {
        napi_throw_error(env, NULL, "NSM returned fewer entropy bytes than requested");
        return NULL;
    }

    napi_value result;
    napi_create_buffer_copy(env, n, entropy, NULL, &result);
    return result;
}

static napi_value js_get_attestation_doc(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    bool is_buf;
    napi_is_buffer(env, argv[0], &is_buf);
    if (!is_buf) { napi_throw_type_error(env, NULL, "expected Buffer"); return NULL; }

    void *pub_key; size_t pub_key_len;
    napi_get_buffer_info(env, argv[0], &pub_key, &pub_key_len);

    uint8_t req[REQ_MAX_SIZE + pub_key_len];
    CborEncoder enc, outer, inner;
    cbor_encoder_init(&enc, req, sizeof(req), 0);
    cbor_encoder_create_map(&enc, &outer, 1);
    cbor_encode_text_string(&outer, "Attestation", 11);
    cbor_encoder_create_map(&outer, &inner, 3);
    cbor_encode_text_string(&inner, "user_data",  9);  cbor_encode_null(&inner);
    cbor_encode_text_string(&inner, "nonce",      5);  cbor_encode_null(&inner);
    cbor_encode_text_string(&inner, "public_key", 10);
    cbor_encode_byte_string(&inner, pub_key, pub_key_len);
    cbor_encoder_close_container(&outer, &inner);
    cbor_encoder_close_container(&enc, &outer);
    uint32_t req_len = (uint32_t)cbor_encoder_get_buffer_size(&enc, req);

    uint8_t resp[RESP_MAX_SIZE];
    uint32_t resp_len = sizeof(resp);
    if (nsm_call(req, req_len, resp, &resp_len) < 0) {
        napi_throw_error(env, NULL, "NSM Attestation ioctl failed");
        return NULL;
    }

    const uint8_t *doc; size_t doc_len;
    if (parse_nested_bytes(resp, resp_len, &doc, &doc_len) != CborNoError) {
        napi_throw_error(env, NULL, "unexpected NSM Attestation response");
        return NULL;
    }

    napi_value result;
    napi_create_buffer_copy(env, doc_len, doc, NULL, &result);
    return result;
}

static napi_value init(napi_env env, napi_value exports) {
    napi_value fn_entropy, fn_attest;
    napi_create_function(env, "getEntropy",        NAPI_AUTO_LENGTH, js_get_entropy,         NULL, &fn_entropy);
    napi_create_function(env, "getAttestationDoc", NAPI_AUTO_LENGTH, js_get_attestation_doc, NULL, &fn_attest);
    napi_set_named_property(env, exports, "getEntropy",        fn_entropy);
    napi_set_named_property(env, exports, "getAttestationDoc", fn_attest);
    return exports;
}

NAPI_MODULE(nsm, init)
