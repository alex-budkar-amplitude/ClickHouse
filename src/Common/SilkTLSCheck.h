#pragma once

#if defined(SILK_TLS_CHECK)
#    define SILK_TLS_BENIGN [[clang::annotate("silk-tls-benign")]]
#    define SILK_FIBER_ENTRYPOINT [[clang::annotate("silk-fiber-entrypoint")]]
#else
#    define SILK_TLS_BENIGN
#    define SILK_FIBER_ENTRYPOINT
#endif

extern "C" void check_silk_tls_access(void * address, const char * name) noexcept;
extern "C" void silk_tls_check_prime() noexcept;

namespace Silk
{

extern thread_local bool inside_silk_fiber;

}
