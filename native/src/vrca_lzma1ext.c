/* Bounded raw LZMA1 input decoder. ABI comes from the platform's lzma.h.
 * A context becomes successful only at STREAM_END with both exact totals.
 * No files, output encoders, signatures, model semantics, or fallback here.
 * The Python feeder preserves 64 final input bytes in one span to avoid
 * liblzma's optional-EOPM known-size state split across input calls.
 */
#define LZMA_API_STATIC
#include <lzma.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define VRCA_API __declspec(dllexport)
typedef const char *(LZMA_API_CALL *version_fn)(void);
typedef lzma_bool (LZMA_API_CALL *supported_fn)(lzma_vli);
typedef lzma_ret (LZMA_API_CALL *decoder_fn)(lzma_stream *, const lzma_filter *);
typedef lzma_ret (LZMA_API_CALL *code_fn)(lzma_stream *, lzma_action);
typedef void (LZMA_API_CALL *end_fn)(lzma_stream *);
static HMODULE vrca_module;
static version_fn api_version;
static supported_fn api_supported;
static decoder_fn api_decoder;
static code_fn api_code;
static end_fn api_end;
#else
#define VRCA_API __attribute__((visibility("default")))
#define api_version lzma_version_string
#define api_supported lzma_filter_decoder_is_supported
#define api_decoder lzma_raw_decoder
#define api_code lzma_code
#define api_end lzma_end
#endif

#define VRCA_MAX_DICT (UINT32_C(64) * 1024 * 1024)
#define VRCA_MAX_BLOCK (UINT64_C(768) * 1024 * 1024)
#define VRCA_MAX_CHUNK (UINT32_C(8) * 1024 * 1024)
#define VRCA_MAGIC UINT32_C(0x564C5A31)

typedef struct {
    lzma_stream stream;
    uint64_t expected_input;
    uint64_t expected_output;
    uint32_t magic;
    int finishing;
    int terminal;
    lzma_ret last_status;
} vrca_decoder;

static int vrca_ready;

VRCA_API int vrca_lzma_init(const wchar_t *runtime_path) {
    if (vrca_ready) return LZMA_OK;
#ifdef _WIN32
    if (runtime_path == NULL || wcslen(runtime_path) < 4 || runtime_path[1] != L':')
        return LZMA_OPTIONS_ERROR;
    vrca_module = LoadLibraryExW(runtime_path, NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (vrca_module == NULL) return LZMA_OPTIONS_ERROR;
#pragma warning(push)
#pragma warning(disable: 4191)
    api_version = (version_fn)GetProcAddress(vrca_module, "lzma_version_string");
    api_supported = (supported_fn)GetProcAddress(vrca_module, "lzma_filter_decoder_is_supported");
    api_decoder = (decoder_fn)GetProcAddress(vrca_module, "lzma_raw_decoder");
    api_code = (code_fn)GetProcAddress(vrca_module, "lzma_code");
    api_end = (end_fn)GetProcAddress(vrca_module, "lzma_end");
#pragma warning(pop)
    if (!api_version || !api_supported || !api_decoder || !api_code || !api_end) {
        FreeLibrary(vrca_module);
        vrca_module = NULL;
        return LZMA_OPTIONS_ERROR;
    }
#else
    if (runtime_path != NULL) return LZMA_OPTIONS_ERROR;
#endif
    if (!api_supported(LZMA_FILTER_LZMA1EXT)) return LZMA_OPTIONS_ERROR;
    vrca_ready = 1;
    return LZMA_OK;
}

VRCA_API const char *vrca_lzma_runtime_version(void) {
    return vrca_ready ? api_version() : "not-initialized";
}

VRCA_API uint32_t vrca_lzma_contract_version(void) { return 1; }

VRCA_API int vrca_lzma_open(const uint8_t *props, size_t props_size,
    uint64_t payload_size, uint64_t expanded_size, void **destination) {
    uint32_t property;
    lzma_options_lzma opt;
    lzma_filter filters[2];
    vrca_decoder *decoder;
    lzma_stream initial = LZMA_STREAM_INIT;
    lzma_ret ret;
    if (!destination) return LZMA_PROG_ERROR;
    *destination = NULL;
    if (!vrca_ready || !props || props_size != 5 || payload_size < 5 ||
        payload_size > VRCA_MAX_BLOCK || expanded_size > VRCA_MAX_BLOCK)
        return LZMA_OPTIONS_ERROR;
    memset(&opt, 0, sizeof(opt));
    property = props[0];
    if (property >= 225) return LZMA_OPTIONS_ERROR;
    opt.dict_size = (uint32_t)props[1] | ((uint32_t)props[2] << 8) |
        ((uint32_t)props[3] << 16) | ((uint32_t)props[4] << 24);
    opt.lc = property % 9;
    opt.lp = (property / 9) % 5;
    opt.pb = property / 45;
    if (opt.dict_size > VRCA_MAX_DICT || opt.lc + opt.lp > 4 || opt.pb > 4)
        return LZMA_OPTIONS_ERROR;
    opt.ext_flags = LZMA_LZMA1EXT_ALLOW_EOPM;
    lzma_set_ext_size(opt, expanded_size);
    filters[0].id = LZMA_FILTER_LZMA1EXT;
    filters[0].options = &opt;
    filters[1].id = LZMA_VLI_UNKNOWN;
    filters[1].options = NULL;
    decoder = (vrca_decoder *)calloc(1, sizeof(*decoder));
    if (!decoder) return LZMA_MEM_ERROR;
    decoder->stream = initial;
    ret = api_decoder(&decoder->stream, filters);
    if (ret != LZMA_OK) {
        api_end(&decoder->stream);
        free(decoder);
        return ret;
    }
    decoder->expected_input = payload_size;
    decoder->expected_output = expanded_size;
    decoder->magic = VRCA_MAGIC;
    *destination = decoder;
    return LZMA_OK;
}

VRCA_API int vrca_lzma_feed(void *context, const uint8_t *input, size_t input_size,
    uint8_t *output, size_t output_capacity, int finish,
    size_t *input_used, size_t *output_used, uint64_t *total_input,
    uint64_t *total_output) {
    vrca_decoder *decoder = (vrca_decoder *)context;
    lzma_ret ret;
    if (!decoder || decoder->magic != VRCA_MAGIC || !input_used || !output_used ||
        !total_input || !total_output) return LZMA_PROG_ERROR;
    *input_used = *output_used = 0;
    *total_input = decoder->stream.total_in;
    *total_output = decoder->stream.total_out;
    if ((!input && input_size) || !output || output_capacity == 0 ||
        input_size > VRCA_MAX_CHUNK || output_capacity > VRCA_MAX_CHUNK ||
        (finish != 0 && finish != 1)) return LZMA_PROG_ERROR;
    if (decoder->terminal) {
        if (decoder->last_status == LZMA_STREAM_END && input_size != 0)
            return LZMA_DATA_ERROR;
        return decoder->last_status;
    }
    if (decoder->finishing && !finish) return LZMA_PROG_ERROR;
    if ((uint64_t)input_size > decoder->expected_input - decoder->stream.total_in) {
        decoder->terminal = 1;
        decoder->last_status = LZMA_DATA_ERROR;
        return LZMA_DATA_ERROR;
    }
    if (finish) decoder->finishing = 1;
    decoder->stream.next_in = input;
    decoder->stream.avail_in = input_size;
    decoder->stream.next_out = output;
    decoder->stream.avail_out = output_capacity;
    ret = api_code(&decoder->stream, finish ? LZMA_FINISH : LZMA_RUN);
    *input_used = input_size - decoder->stream.avail_in;
    *output_used = output_capacity - decoder->stream.avail_out;
    *total_input = decoder->stream.total_in;
    *total_output = decoder->stream.total_out;
    if (*total_input > decoder->expected_input || *total_output > decoder->expected_output)
        ret = LZMA_DATA_ERROR;
    if (ret == LZMA_STREAM_END && (*total_input != decoder->expected_input ||
        *total_output != decoder->expected_output)) ret = LZMA_DATA_ERROR;
    if (ret != LZMA_OK) {
        decoder->terminal = 1;
        decoder->last_status = ret;
    }
    return (int)ret;
}

VRCA_API void vrca_lzma_close(void *context) {
    vrca_decoder *decoder = (vrca_decoder *)context;
    if (!decoder || decoder->magic != VRCA_MAGIC) return;
    decoder->magic = 0;
    api_end(&decoder->stream);
    free(decoder);
}
