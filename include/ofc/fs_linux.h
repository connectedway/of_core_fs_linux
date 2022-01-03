/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#if !defined(__OFC_FSLINUX_H__)
#define __OFC_FSLINUX_H__

#include "ofc/types.h"
#include "ofc/file.h"

#define OFC_FS_LINUX_BLOCK_SIZE 512

/**
 * \defgroup fs_linux Linux File System Dependent Support
 * \ingroup fs
 */

/** \{ */

#if defined(__cplusplus)
extern "C"
{
#endif

OFC_VOID OfcFSLinuxDestroyOverlapped(OFC_HANDLE hOverlapped);

OFC_VOID
OfcFSLinuxSetOverlappedOffset(OFC_HANDLE hOverlapped, OFC_OFFT offset);

OFC_VOID OfcFSLinuxStartup(OFC_VOID);

OFC_VOID OfcFSLinuxShutdown(OFC_VOID);

int OfcFSLinuxGetFD(OFC_HANDLE);

OFC_HANDLE OfcFSLinuxGetOverlappedEvent(OFC_HANDLE hOverlapped);

#if defined(__cplusplus)
}
#endif

#endif

/** \} */
