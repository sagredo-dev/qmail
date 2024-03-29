#ifndef DEPRECATED_H
#define DEPRECATED_H

/*
 * Patch grabbed from notqmail https://github.com/notqmail/notqmail/commit/c3d3c72e3ca7bb5102f710aad7bf9ab105bde27e
 * It gets the compiler to get rid of "incompatible redeclaration of library function 'log2'"
 * compilation warning.
 *
 * We sometimes decide certain functions should no longer be called.
 * If valuable external patches still call them, we wait to delete them
 * until those patches stop being valuable.
 *
 * In the meantime, we
 *
 * 1. Mark these functions deprecated, so compilers will warn people
 * 2. Optionally define them out of existence, mainly for developer builds
 */

#ifndef DEPRECATED_FUNCTIONS_REMOVED
#define DEPRECATED_FUNCTIONS_AVAILABLE
#endif

#if defined(__clang__) || defined(__GNUC__)
#define _deprecated_ __attribute__((deprecated))
#else
#define _deprecated_
#endif

#endif
