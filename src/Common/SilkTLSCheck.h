#pragma once

#if defined(SILK_TLS_CHECK)
#    define SILK_TLS_BENIGN [[clang::annotate("silk-tls-benign")]]
#else
#    define SILK_TLS_BENIGN
#endif

extern "C" void check_silk_tls_access(void * address, const char * name) noexcept;

namespace Silk
{

extern thread_local bool inside_silk_fiber;

}
