#!/usr/bin/env python3
"""Patch the upstream signing constant inside the prebuilt libtmessages.

libtmessages returns JNI_ERR from JNI_OnLoad when the running APK certificate
SHA1 does not match the value baked into the binary. Repackaged builds sign with
a different key, so the constant is rewritten to the key used by this project.
"""
import glob
import os
import sys

OLD = b"3A0F57FE06485D0B90D0ACD990E3A30328E3988D"
NEW = b"9A82879F1F55784885C82450BE629BD54A204A4D"


def main(directory):
    files = glob.glob(os.path.join(directory, "libtmessages.*.so"))
    if not files:
        print("no libtmessages found in", directory)
        return 1
    for path in files:
        with open(path, "rb") as f:
            data = f.read()
        count = data.count(OLD)
        if count:
            with open(path, "wb") as f:
                f.write(data.replace(OLD, NEW))
        print(path, "patched", count)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
