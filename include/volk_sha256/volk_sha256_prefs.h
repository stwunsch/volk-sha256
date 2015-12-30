#ifndef INCLUDED_VOLK_SHA256_PREFS_H
#define INCLUDED_VOLK_SHA256_PREFS_H

#include <volk_sha256/volk_sha256_common.h>
#include <stdlib.h>

__VOLK_DECL_BEGIN

typedef struct volk_sha256_arch_pref
{
    char name[128];   //name of the kernel
    char impl_a[128]; //best aligned impl
    char impl_u[128]; //best unaligned impl
} volk_sha256_arch_pref_t;

////////////////////////////////////////////////////////////////////////
// get path to volk_sha256_config profiling info;
// returns \0 in the argument on failure.
////////////////////////////////////////////////////////////////////////
VOLK_API void volk_sha256_get_config_path(char *);

////////////////////////////////////////////////////////////////////////
// load prefs into global prefs struct
////////////////////////////////////////////////////////////////////////
VOLK_API size_t volk_sha256_load_preferences(volk_sha256_arch_pref_t **);

__VOLK_DECL_END

#endif //INCLUDED_VOLK_SHA256_PREFS_H
