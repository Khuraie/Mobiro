#!/usr/bin/env python3
"""
Patches upstream Mesa's src/android_stub/ so libvulkan_freedreno.so has ZERO
private Android HAL/VNDK DT_NEEDED dependencies (libhardware.so, libsync.so,
libbacktrace.so), which are blocked in Android 15/16 app linker namespaces (clns-*).

- hardware_stub.cpp -> static_library returning -ENOENT (clean gralloc0 fallback)
- sync_stub.cpp     -> static_library backed by real Linux kernel sync_file poll()/ioctl()
- log / nativewindow -> kept dynamic (both are public Android NDK libraries in clns-*)
"""

import pathlib
import sys


HARDWARE_STUB_CPP = r"""#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <hardware/hardware.h>
#include <vndk/hardware_buffer.h>

extern "C" {

int hw_get_module(const char *id, const struct hw_module_t **module)
{
   (void)id;
   if (module)
      *module = NULL;
   return -ENOENT;
}

/* Dynamic VNDK bridge: resolves AHardwareBuffer_getNativeHandle at runtime when exported,
 * and returns NULL instead of failing dlopen() on Android 15/16 app namespaces (clns-*). */
const native_handle_t *AHardwareBuffer_getNativeHandle(const AHardwareBuffer *buffer)
{
   typedef const native_handle_t *(*PfnGetNativeHandle)(const AHardwareBuffer *);
   static PfnGetNativeHandle pfn = NULL;
   static int resolved = 0;
   if (!resolved) {
      resolved = 1;
      void *h = dlopen("libnativewindow.so", RTLD_NOW | RTLD_NOLOAD);
      if (!h)
         h = dlopen("libnativewindow.so", RTLD_NOW | RTLD_LOCAL);
      if (h)
         pfn = (PfnGetNativeHandle)dlsym(h, "AHardwareBuffer_getNativeHandle");
   }
   return pfn ? pfn(buffer) : NULL;
}

}
"""

SYNC_STUB_CPP = r"""#include <errno.h>
#include <linux/sync_file.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sync/sync.h>

extern "C" {

/* Real Linux kernel dma_fence sync_file wait (avoids private Android libsync.so) */
int sync_wait(int fd, int timeout)
{
   struct pollfd fds;
   fds.fd = fd;
   fds.events = POLLIN;
   fds.revents = 0;
   int ret;
   do {
      ret = poll(&fds, 1, timeout);
      if (ret > 0) {
         if (fds.revents & (POLLERR | POLLNVAL)) {
            errno = EINVAL;
            return -1;
         }
         return 0;
      } else if (ret == 0) {
         errno = ETIME;
         return -1;
      }
   } while (ret == -1 && (errno == EINTR || errno == EAGAIN));
   return ret;
}

int sync_merge(const char *name, int fd, int fd2)
{
   struct sync_merge_data data;
   memset(&data, 0, sizeof(data));
   data.fd2 = fd2;
   data.fence = -1;
   if (name) {
      strncpy(data.name, name, sizeof(data.name) - 1);
      data.name[sizeof(data.name) - 1] = '\0';
   }
   int err = ioctl(fd, SYNC_IOC_MERGE, &data);
   if (err < 0)
      return err;
   return data.fence;
}

struct sync_file_info *sync_file_info(int32_t fd)
{
   struct sync_file_info *info = (struct sync_file_info *)calloc(1, sizeof(*info));
   if (!info)
      return NULL;
   if (ioctl(fd, SYNC_IOC_FILE_INFO, info) < 0) {
      free(info);
      return NULL;
   }
   return info;
}

void sync_file_info_free(struct sync_file_info *info)
{
   free(info);
}

}
"""

ANDROID_STUB_MESON = r"""# Patched by Mobiro (scripts/patch_turnip_android_stubs.py) for Android 15/16 clns-* compatibility
if with_android_stub
  static_stub_libs = []
  foreach lib : ['hardware', 'sync']
    static_stub_libs += static_library(
      'mobiro_android_' + lib,
      files(lib + '_stub.cpp'),
      include_directories : inc_include,
      install : false,
    )
  endforeach

  shared_stub_libs = []
  foreach lib : ['log', 'nativewindow']
    shared_stub_libs += shared_library(
      lib,
      files(lib + '_stub.cpp'),
      include_directories : inc_include,
      install : false,
    )
  endforeach

  dep_android = declare_dependency(
    link_with : shared_stub_libs + static_stub_libs,
  )
endif
"""


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: patch_turnip_android_stubs.py <mesa_src_dir>", file=sys.stderr)
        return 2
    mesa_src = pathlib.Path(sys.argv[1])
    stub_dir = mesa_src / "src" / "android_stub"
    if not stub_dir.is_dir():
        print(f"[Mobiro] Missing Mesa android_stub directory: {stub_dir}", file=sys.stderr)
        return 1

    (stub_dir / "hardware_stub.cpp").write_text(HARDWARE_STUB_CPP, encoding="utf-8")
    (stub_dir / "sync_stub.cpp").write_text(SYNC_STUB_CPP, encoding="utf-8")
    (stub_dir / "meson.build").write_text(ANDROID_STUB_MESON, encoding="utf-8")

    # Remove AHardwareBuffer_getNativeHandle from nativewindow_stub.cpp so ld resolves it
    # against our static dlsym bridge in hardware_stub.cpp instead of an UND dynamic import.
    nw_path = stub_dir / "nativewindow_stub.cpp"
    if nw_path.is_file():
        nw_txt = nw_path.read_text(encoding="utf-8")
        marker = "const native_handle_t *\nAHardwareBuffer_getNativeHandle(const AHardwareBuffer *buffer)\n{\n   return NULL;\n}"
        if marker in nw_txt:
            nw_path.write_text(nw_txt.replace(marker, "/* AHardwareBuffer_getNativeHandle bridged in hardware_stub.cpp */"), encoding="utf-8")

    print(f"[Mobiro] Patched Mesa android_stub at {stub_dir} (static hardware/sync/VNDK-handle, dynamic public NDK log/nativewindow)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
