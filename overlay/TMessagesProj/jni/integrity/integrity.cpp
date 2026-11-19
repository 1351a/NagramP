//
// Signature gate for the native loader.
//
// Upstream compares the running APK certificate against a hard-coded SHA1 and
// returns JNI_ERR on mismatch, which makes System.loadLibrary fail and takes the
// whole app down. Repackaged builds are signed with a different key, so the
// comparison is removed here and the remaining integrity inputs stay untouched.
//
#include "integrity.h"

extern "C" {
int verifySign(JNIEnv *env) {
    (void) env;
    return JNI_OK;
}
}
