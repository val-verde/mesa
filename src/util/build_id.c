/*
 * Copyright © 2016 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifdef HAVE_DL_ITERATE_PHDR
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>
#include <string.h>

#include "build_id.h"
#include "macros.h"

#ifndef NT_GNU_BUILD_ID
#define NT_GNU_BUILD_ID 3
#endif

#ifndef ElfW
#define ElfW(type) Elf_##type
#endif

#ifdef __ANDROID__
#include <elf.h>
#include <sys/auxv.h>
#include <sys/types.h>
#include <link.h>

/* ld provides this to us in the default link script */
extern void* __executable_start;

int dl_iterate_phdr(int (*cb)(struct dl_phdr_info* info, size_t size, void* data), void* data) {
#if defined(__aarch64__) || defined(__x86_64__)
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*) &__executable_start;
#else
    Elf32_Ehdr* ehdr = (Elf32_Ehdr*) &__executable_start;
#endif
    // TODO: again, copied from linker.c. Find a better home for this later.
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0) return -1;
    if (ehdr->e_ident[EI_MAG1] != ELFMAG1) return -1;
    if (ehdr->e_ident[EI_MAG2] != ELFMAG2) return -1;
    if (ehdr->e_ident[EI_MAG3] != ELFMAG3) return -1;
    // Dynamic binaries get their dl_iterate_phdr from the dynamic linker, but
    // static binaries get this. We don't have a list of shared objects to
    // iterate over, since there's really only a single monolithic blob of
    // code/data, plus optionally a VDSO.
    struct dl_phdr_info exe_info;
    exe_info.dlpi_addr = 0;
    exe_info.dlpi_name = NULL;
#if defined(__aarch64__) || defined(__x86_64__)
    exe_info.dlpi_phdr = (Elf64_Phdr*) ((unsigned long) ehdr + ehdr->e_phoff);
#else
    exe_info.dlpi_phdr = (Elf32_Phdr*) ((unsigned long) ehdr + ehdr->e_phoff);
#endif
    exe_info.dlpi_phnum = ehdr->e_phnum;
#ifdef AT_SYSINFO_EHDR
    // Try the executable first.
    int rc = cb(&exe_info, sizeof(exe_info), data);
    if (rc != 0) {
        return rc;
    }
    // Try the VDSO if that didn't work.
#if defined(__aarch64__) || defined(__x86_64__)
    Elf64_Ehdr* ehdr_vdso = (Elf64_Ehdr*) getauxval(AT_SYSINFO_EHDR);
#else
    Elf32_Ehdr* ehdr_vdso = (Elf32_Ehdr*) getauxval(AT_SYSINFO_EHDR);
#endif
    struct dl_phdr_info vdso_info;
    vdso_info.dlpi_addr = 0;
    vdso_info.dlpi_name = NULL;
#if defined(__aarch64__) || defined(__x86_64__)
    vdso_info.dlpi_phdr = (Elf64_Phdr*) ((char*) ehdr_vdso + ehdr_vdso->e_phoff);
#else
    vdso_info.dlpi_phdr = (Elf32_Phdr*) ((char*) ehdr_vdso + ehdr_vdso->e_phoff);
#endif
    vdso_info.dlpi_phnum = ehdr_vdso->e_phnum;
    for (size_t i = 0; i < vdso_info.dlpi_phnum; ++i) {
        if (vdso_info.dlpi_phdr[i].p_type == PT_LOAD) {
        #if defined(__aarch64__) || defined(__x86_64__)
            vdso_info.dlpi_addr = (Elf64_Addr) ehdr_vdso - vdso_info.dlpi_phdr[i].p_vaddr;
	#else
            vdso_info.dlpi_addr = (Elf32_Addr) ehdr_vdso - vdso_info.dlpi_phdr[i].p_vaddr;
	#endif
            break;
        }
    }
    return cb(&vdso_info, sizeof(vdso_info), data);
#else
    // There's only the executable to try.
    return cb(&exe_info, sizeof(exe_info), data);
#endif
}
#endif

struct build_id_note {
   ElfW(Nhdr) nhdr;

   char name[4]; /* Note name for build-id is "GNU\0" */
   uint8_t build_id[0];
};

struct callback_data {
   /* Base address of shared object, taken from Dl_info::dli_fbase */
   const void *dli_fbase;

   struct build_id_note *note;
};

static int
build_id_find_nhdr_callback(struct dl_phdr_info *info, size_t size, void *data_)
{
   struct callback_data *data = data_;

   /* Calculate address where shared object is mapped into the process space.
    * (Using the base address and the virtual address of the first LOAD segment)
    */
   void *map_start = NULL;
   for (unsigned i = 0; i < info->dlpi_phnum; i++) {
      if (info->dlpi_phdr[i].p_type == PT_LOAD) {
         map_start = (void *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
         break;
      }
   }

   if (map_start != data->dli_fbase)
      return 0;

   for (unsigned i = 0; i < info->dlpi_phnum; i++) {
      if (info->dlpi_phdr[i].p_type != PT_NOTE)
         continue;

      struct build_id_note *note = (void *)(info->dlpi_addr +
                                            info->dlpi_phdr[i].p_vaddr);
      ptrdiff_t len = info->dlpi_phdr[i].p_filesz;

      while (len >= sizeof(struct build_id_note)) {
         if (note->nhdr.n_type == NT_GNU_BUILD_ID &&
            note->nhdr.n_descsz != 0 &&
            note->nhdr.n_namesz == 4 &&
            memcmp(note->name, "GNU", 4) == 0) {
            data->note = note;
            return 1;
         }

         size_t offset = sizeof(ElfW(Nhdr)) +
                         ALIGN_POT(note->nhdr.n_namesz, 4) +
                         ALIGN_POT(note->nhdr.n_descsz, 4);
         note = (struct build_id_note *)((char *)note + offset);
         len -= offset;
      }
   }

   return 0;
}

const struct build_id_note *
build_id_find_nhdr_for_addr(const void *addr)
{
   Dl_info info;

   if (!dladdr(addr, &info))
      return NULL;

   if (!info.dli_fbase)
      return NULL;

   struct callback_data data = {
      .dli_fbase = info.dli_fbase,
      .note = NULL,
   };

   if (!dl_iterate_phdr(build_id_find_nhdr_callback, &data))
      return NULL;

   return data.note;
}

unsigned
build_id_length(const struct build_id_note *note)
{
   return note->nhdr.n_descsz;
}

const uint8_t *
build_id_data(const struct build_id_note *note)
{
   return note->build_id;
}

#endif
