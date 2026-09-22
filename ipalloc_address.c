#include "ipalloc_address.h"
#include "alloc.h"            // per le funzioni alloc/alloc_free
#include "gen_allocdefs.h"    // per le macro interne di gen_alloc

/* Generate readyplus and append implementations for struct ip_address arrays */
GEN_ALLOC_readyplus(ipalloc_address, struct ip_address, ia, len, a, i, n, x, 10, ipalloc_address_readyplus)
GEN_ALLOC_append(ipalloc_address, struct ip_address, ia, len, a, i, n, x, 10, ipalloc_address_readyplus, ipalloc_address_append)
