.. SPDX-License-Identifier: GPL-2.0-or-later

=====================================
HWPoison list preservation across KHO
=====================================

When a page is hard-offlined due to an uncorrectable memory error the
kernel sets ``PG_hwpoison`` on the page, removes it from the buddy
allocator and keeps it out for the rest of the boot. The next kernel
started via ``kexec`` does not by default inherit that list, so it sees
the page as ordinary system RAM and can hand it back out from the
allocator on a fresh allocation.

The optional ``CONFIG_MEMORY_FAILURE_KHO`` Kconfig closes this gap by
recording every poisoned PFN into a Kexec HandOver (KHO) subtree and
replaying the list in the next kernel before the buddy allocator hands
the pages out.

This document expects familiarity with the base KHO
:ref:`concepts <kho-concepts>`.

Prerequisites
=============

* ``CONFIG_MEMORY_FAILURE=y``
* ``CONFIG_KEXEC_HANDOVER=y``
* ``CONFIG_MEMORY_FAILURE_KHO=y`` (defaults to ``y`` when both of the
  above are set)
* Boot with ``kho=on`` on both the producing and the consuming kernel.

ABI
===

The subtree follows the same plain-struct pattern as
``kexec-metadata``. The blob registered via ``kho_add_subtree()`` is a
``struct kho_hwpoison_metadata`` defined in
``include/linux/kho/abi/hwpoison.h``::

  struct kho_hwpoison_metadata {
          u32 version;                 /* KHO_HWPOISON_METADATA_VERSION */
          u32 _pad;
          u64 count;                   /* live entries in the PFN array */
          struct kho_vmalloc pfns;     /* preserved u64[] of PFNs */
  } __packed;

The ``pfns`` handle points at the preserved ``vmalloc`` array that
holds the actual PFNs; the producer grows that array by powers of two
as needed and writes the fresh ``kho_vmalloc`` descriptor back into the
in-place header so the next kexec sees the up-to-date list. The header
itself lives on a single KHO-preserved page allocated with
``kho_alloc_preserve()``.

How it works
============

Every successful poison event flows through
``num_poisoned_pages_inc()``. The hook appends the PFN to the
``vmalloc`` array referenced from the header and ensures the header
is published as the ``"hwpoison"`` subtree.

Unpoison events (``num_poisoned_pages_sub()``) remove the PFN from
the array so an explicitly unpoisoned page is not resurrected in the
next kernel.

On the receive side a ``late_initcall`` calls
``kho_retrieve_subtree("hwpoison")``, sanity-checks the blob size and
the version field, restores the ``vmalloc`` array via
``kho_restore_vmalloc()`` and runs ``memory_failure(pfn, 0)`` on each
entry. The pages are still in the buddy free-list at that point, so
``memory_failure()`` takes them off via ``take_page_off_buddy()`` and
sets ``PG_hwpoison`` again.

The replay re-enters the producer, so the same set is published into
the new kernel's outgoing subtree and survives any chain of kexec
transitions.

Verifying
=========

After the kexec, the post-handover dmesg contains a line of the form::

  hwpoison-kho: re-poisoning N pages from previous kernel

and ``/proc/meminfo`` reports the same ``HardwareCorrupted`` value as
the previous kernel did at the moment of kexec.

Limitations
===========

* Poison events that happen before the KHO infrastructure is ready
  (before ``kho_init`` runs at ``fs_initcall``) cannot be published.
  This is academic in practice because MCEs do not fire that early in
  boot.

* The PFN list is one ``u64`` per page; one million bad pages costs
  8 MiB of preserved memory.

* The mechanism is per-page. Cross-boot retirement of an entire DIMM
  is the firmware's responsibility (BMC page retirement, DDR PPR,
  CXL device poison lists, etc.).
