#pragma once

// The public local build has no VMProtect or licensing SDK dependency. These
// markers intentionally remain no-ops so the analysis code stays readable
// without introducing a proprietary runtime or account boundary.
#define VRC_VMP_BEGIN_ULTRA(name) do { (void)sizeof(name); } while (0)
#define VRC_VMP_BEGIN_VIRTUAL(name) do { (void)sizeof(name); } while (0)
#define VRC_VMP_BEGIN_MUTATION(name) do { (void)sizeof(name); } while (0)
#define VRC_VMP_BEGIN_LOCKED(name) do { (void)sizeof(name); } while (0)
#define VRC_VMP_END() do {} while (0)
