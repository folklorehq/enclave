#include <node_api.h>
#include <linux/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define NSM_IOCTL_MAGIC 0x0A

struct nsm_iovec {
    __u64 addr;
    __u64 len;
};

struct nsm_raw {
    struct nsm_iovec request;
    struct nsm_iovec response;
};

#define NSM_IOCTL _IOWR(NSM_IOCTL_MAGIC, 0, struct nsm_raw)
#define NSM_DEV "/dev/nsm"
#define REQ_MAX_SIZE 512
#define RESP_MAX_SIZE (16 * 1024)

static void secure_zero(void *buffer, size_t size) {
    volatile uint8_t *bytes = buffer;
    while (size-- > 0) *bytes++ = 0;
}

static int nsm_call(const uint8_t *request, uint64_t request_size,
                    uint8_t *response, uint64_t *response_size) {
    int fd = open(NSM_DEV, O_RDWR);
    if (fd < 0) return -1;
    struct nsm_raw args = {
        .request = {
            .addr = (__u64)(uintptr_t)request,
            .len = (__u64)request_size,
        },
        .response = {
            .addr = (__u64)(uintptr_t)response,
            .len = (__u64)*response_size,
        },
    };
    int rc = ioctl(fd, NSM_IOCTL, &args);
    close(fd);
    if (rc < 0 || args.response.len > RESP_MAX_SIZE) return -1;
    *response_size = args.response.len;
    return 0;
}

static napi_value js_call(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_status status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok || argc != 1) {
        napi_throw_type_error(env, NULL, "invalid NSM request");
        return NULL;
    }

    bool is_buffer = false;
    status = napi_is_buffer(env, argv[0], &is_buffer);
    if (status != napi_ok || !is_buffer) {
        napi_throw_type_error(env, NULL, "invalid NSM request");
        return NULL;
    }

    void *input = NULL;
    size_t input_size = 0;
    status = napi_get_buffer_info(env, argv[0], &input, &input_size);
    if (status != napi_ok || input_size == 0 || input_size > REQ_MAX_SIZE) {
        napi_throw_range_error(env, NULL, "invalid NSM request");
        return NULL;
    }

    uint8_t request[REQ_MAX_SIZE];
    uint8_t response[RESP_MAX_SIZE];
    uint64_t response_size = RESP_MAX_SIZE;
    napi_value result = NULL;
    memcpy(request, input, input_size);
    if (nsm_call(request, (uint64_t)input_size, response, &response_size) != 0 ||
        response_size == 0) {
        secure_zero(request, sizeof(request));
        secure_zero(response, sizeof(response));
        napi_throw_error(env, NULL, "NSM ioctl failed");
        return NULL;
    }

    status = napi_create_buffer_copy(env, response_size, response, NULL, &result);
    secure_zero(request, sizeof(request));
    secure_zero(response, sizeof(response));
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "NSM response failed");
        return NULL;
    }
    return result;
}

static napi_value init(napi_env env, napi_value exports) {
    napi_value call = NULL;
    if (napi_create_function(env, "call", NAPI_AUTO_LENGTH, js_call, NULL, &call) != napi_ok ||
        napi_set_named_property(env, exports, "call", call) != napi_ok) {
        napi_throw_error(env, NULL, "NSM initialization failed");
        return NULL;
    }
    return exports;
}

NAPI_MODULE(nsm, init)
