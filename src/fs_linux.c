/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#define __USE_MISC
#define _XOPEN_SOURCE 500

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/file.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <aio.h>
#include <signal.h>

#include "ofc/types.h"
#include "ofc/handle.h"
#include "ofc/queue.h"
#include "ofc/libc.h"
#include "ofc/path.h"
#include "ofc/lock.h"
#include "ofc/event.h"
#include "ofc/thread.h"
#include "ofc/time.h"
#include "ofc/process.h"
#if defined(OFC_PERF_STATS)
#include "ofc/perf.h"
#endif

#include "ofc/heap.h"
#include "ofc/fs.h"

#include "ofc/fs_linux.h"
#include "ofc/fs_match.h"

/**
 * \defgroup fs_linux Linux File Interface
 *
 */

/** \{ */
typedef struct {
    int fd;
    OFC_BOOL deleteOnClose;
    OFC_CHAR *name;
    OFC_CHAR *pattern;
    DIR *dir;
    struct dirent *nextDirent;
    int nextRet;
    OFC_BOOL backup;
} OFC_FS_LINUX_CONTEXT;

typedef enum {
    OFC_FSLINUX_READ,
    OFC_FSLINUX_WRITE,
    OFC_FSLINUX_NOOP
} OFC_FSLINUX_OP;

typedef struct {
    OFC_FSLINUX_OP opcode;
    OFC_HANDLE hEvent;
    OFC_HANDLE hBusy;
    OFC_INT dwResult;
    OFC_INT Errno;
    OFC_OFFT offset;
    OFC_HANDLE hThread;
    OFC_LPCVOID lpBuffer;
    OFC_DWORD nNumberOfBytes;
    OFC_INT fd;
} OFC_FSLINUX_OVERLAPPED;

static OFC_HANDLE OfcFSLinuxAIOFreeQ;
static OFC_INT g_instance;
#if defined(OFC_PERF_STATS)
static struct perf_queue *pqueue_read;
static struct perf_queue *pqueue_write;
static struct perf_rt *prt_read;
static struct perf_rt *prt_write;
#endif

/*
 * Error codes
 */
typedef struct {
    OFC_UINT32 file_errno;
    OFC_UINT32 ofc_error;
} ERRNO2FILE;

#define ERRNO2FILE_MAX 34
static ERRNO2FILE errno2file[ERRNO2FILE_MAX] =
  {
    {EPERM, OFC_ERROR_ACCESS_DENIED},
    {ENOENT, OFC_ERROR_FILE_NOT_FOUND},
    {ESRCH, OFC_ERROR_INVALID_HANDLE},
    {EINTR, OFC_ERROR_GEN_FAILURE},
    {EIO, OFC_ERROR_IO_DEVICE},
    {ENXIO, OFC_ERROR_BAD_DEVICE},
    {EBADF, OFC_ERROR_INVALID_HANDLE},
    {EAGAIN, OFC_ERROR_IO_INCOMPLETE},
    {EACCES, OFC_ERROR_INVALID_ACCESS},
    {EFAULT, OFC_ERROR_INVALID_PARAMETER},
    {EBUSY, OFC_ERROR_BUSY},
    {EEXIST, OFC_ERROR_FILE_EXISTS},
    {EXDEV, OFC_ERROR_NOT_SAME_DEVICE},
    {ENOTDIR, OFC_ERROR_INVALID_ACCESS},
    {EISDIR, OFC_ERROR_DIRECTORY},
    {EINVAL, OFC_ERROR_BAD_ARGUMENTS},
    {ENFILE, OFC_ERROR_TOO_MANY_OPEN_FILES},
    {EMFILE, OFC_ERROR_TOO_MANY_OPEN_FILES},
    {ETXTBSY, OFC_ERROR_BUSY},
    {EFBIG, OFC_ERROR_FILE_INVALID},
    {ENOSPC, OFC_ERROR_DISK_FULL},
    {ESPIPE, OFC_ERROR_SEEK_ON_DEVICE},
    {EROFS, OFC_ERROR_WRITE_PROTECT},
    {EPIPE, OFC_ERROR_BROKEN_PIPE},
    {EDEADLK, OFC_ERROR_LOCK_VIOLATION},
    {ENAMETOOLONG, OFC_ERROR_BAD_PATHNAME},
    {ENOSYS, OFC_ERROR_NOT_SUPPORTED},
    {ENOTEMPTY, OFC_ERROR_DIR_NOT_EMPTY},
    {ELOOP, OFC_ERROR_BAD_PATHNAME},
    {EOVERFLOW, OFC_ERROR_BUFFER_OVERFLOW},
    {EOPNOTSUPP, OFC_ERROR_NOT_SUPPORTED},
    {EINPROGRESS, OFC_ERROR_IO_PENDING},
    {EDQUOT, OFC_ERROR_HANDLE_DISK_FULL},
    {ECANCELED, OFC_ERROR_OPERATION_ABORTED}
  };

static OFC_DWORD
OfcFSLinuxAIOThread(OFC_HANDLE hThread, OFC_VOID *context);

static OFC_UINT32 TranslateError(OFC_UINT32 file_errno)
{
  OFC_INT low;
  OFC_INT high;
  OFC_INT cursor;
  OFC_UINT32 ofc_error;

  ofc_error = OFC_ERROR_GEN_FAILURE;
  low = 0;
  high = ERRNO2FILE_MAX - 1;
  cursor = high + low / 2;
  while (errno2file[cursor].file_errno != file_errno && low <= high) {
    if (file_errno < errno2file[cursor].file_errno)
      high = cursor - 1;
    else
      low = cursor + 1;
    cursor = high + low / 2;
  }
  if (errno2file[cursor].file_errno == file_errno)
    ofc_error = errno2file[cursor].ofc_error;

  return (ofc_error);
}

static int Win32DesiredAccessToLinuxFlags(OFC_DWORD dwDesiredAccess)
{
  static OFC_DWORD dwWriteAccess =
    OFC_FILE_ADD_FILE | OFC_FILE_ADD_SUBDIRECTORY |
    OFC_FILE_APPEND_DATA |
    OFC_FILE_DELETE_CHILD |
    OFC_FILE_WRITE_ATTRIBUTES | OFC_FILE_WRITE_DATA |
    OFC_FILE_WRITE_EA |
    OFC_GENERIC_WRITE;
  static OFC_DWORD dwReadAccess =
    OFC_FILE_LIST_DIRECTORY |
    OFC_FILE_READ_ATTRIBUTES | OFC_FILE_READ_DATA |
    OFC_FILE_READ_EA | OFC_FILE_TRAVERSE |
    OFC_GENERIC_READ;
  static OFC_DWORD dwExecuteAccess =
    OFC_FILE_EXECUTE |
    OFC_GENERIC_EXECUTE;

  int oflag;

  oflag = 0;
  if (dwDesiredAccess & dwWriteAccess) {
    if ((dwDesiredAccess & dwReadAccess) ||
	(dwDesiredAccess & dwExecuteAccess))
      oflag = O_RDWR;
    else
      oflag = O_WRONLY;
  } else
    oflag = O_RDONLY;

  return (oflag);
}

static int
Win32CreationDispositionToLinuxFlags(OFC_DWORD dwCreationDisposition)
{
  int oflag;

  static int map[6] =
    {
     /* Unused - 0 */
     0,
     /* Create New - 1 */
     O_CREAT | O_EXCL,
     /* Create Always - 2 */
     O_CREAT | O_TRUNC,
     /* Open Existing - 3 */
     0,
     /* Open Always - 4 */
     O_CREAT,
     /* Truncate Existing - 5 */
     O_TRUNC
    };

  oflag = 0;
  if (dwCreationDisposition >= OFC_CREATE_NEW &&
      dwCreationDisposition <= OFC_TRUNCATE_EXISTING)
    oflag = map[dwCreationDisposition];
  return (oflag);
}

static OFC_VOID Win32OpenModesToLinuxModes(OFC_DWORD dwDesiredAccess,
					   OFC_DWORD dwShareMode,
					   OFC_DWORD dwCreationDisposition,
					   OFC_DWORD dwFlagsAndAttributes,
					   int *oflag, mode_t *mode)
{
  *mode = S_IRWXU | S_IRWXG | S_IRWXO;

  /*
   * First do dwDesired Access
   */
  *oflag = 0;
  *oflag |= Win32DesiredAccessToLinuxFlags(dwDesiredAccess);
  /*
   * Linux doesn't have a share mode
   */
  /*
   * Creation Disposition
   */
  *oflag |= Win32CreationDispositionToLinuxFlags(dwCreationDisposition);
  /*
   * Some stragglers
   */
  if (dwDesiredAccess & OFC_FILE_APPEND_DATA &&
      (!(dwDesiredAccess & OFC_FILE_WRITE_DATA)))
    *oflag |= O_APPEND ;
}

static OFC_LPSTR FilePath2LinuxPath(OFC_LPCTSTR lpFileName)
{
  OFC_LPCTSTR p;
  OFC_LPSTR lpAsciiName;

  p = lpFileName;
  if (ofc_tstrncmp(lpFileName, TSTR("file:"), 5) == 0)
    p = lpFileName + 5;
  lpAsciiName = ofc_tstr2cstr(p);

  return (lpAsciiName);
}

static OFC_HANDLE OfcFSLinuxCreateFile(OFC_LPCTSTR lpFileName,
				       OFC_DWORD dwDesiredAccess,
				       OFC_DWORD dwShareMode,
				       OFC_LPSECURITY_ATTRIBUTES
				       lpSecAttributes,
				       OFC_DWORD dwCreationDisposition,
				       OFC_DWORD dwFlagsAndAttributes,
				       OFC_HANDLE hTemplateFile)
{
  OFC_HANDLE ret;
  OFC_FS_LINUX_CONTEXT *context;
  int oflag;
  mode_t mode;
  OFC_CHAR *lpAsciiName;

  context = ofc_malloc(sizeof(OFC_FS_LINUX_CONTEXT));
  context->fd = -1;
  context->deleteOnClose = OFC_FALSE;
  context->backup = OFC_FALSE;

  Win32OpenModesToLinuxModes(dwDesiredAccess, dwShareMode,
			     dwCreationDisposition, dwFlagsAndAttributes,
			     &oflag, &mode);

  if (dwFlagsAndAttributes & OFC_FILE_FLAG_DELETE_ON_CLOSE)
    context->deleteOnClose = OFC_TRUE;

  /*
   * Strip and convert to non-unicode
   */
  lpAsciiName = FilePath2LinuxPath(lpFileName);

  context->name = ofc_strdup(lpAsciiName);

  if (!(dwFlagsAndAttributes & OFC_FILE_FLAG_BACKUP_SEMANTICS)) {
    context->fd = open(lpAsciiName, oflag, mode);
    if (context->fd < 0) {
      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(errno));
      ofc_free(context->name);
      ofc_free(context);
      ret = OFC_INVALID_HANDLE_VALUE;
    } else
      ret = ofc_handle_create(OFC_HANDLE_FSLINUX_FILE, context);
  } else {
    ret = ofc_handle_create(OFC_HANDLE_FSLINUX_FILE, context);
    context->backup = OFC_TRUE;
  }

  ofc_free(lpAsciiName);

  return (ret);
}

static OFC_BOOL
OfcFSLinuxCreateDirectory(OFC_LPCTSTR lpPathName,
			  OFC_LPSECURITY_ATTRIBUTES lpSecurityAttr)
{
  OFC_BOOL ret;
  int status;
  mode_t mode;
  OFC_CHAR *lpAsciiName;

  lpAsciiName = FilePath2LinuxPath(lpPathName);
  mode = S_IRWXU | S_IRWXG | S_IRWXO;

  status = mkdir(lpAsciiName, mode);

  ofc_free(lpAsciiName);
  if (status < 0) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
    ret = OFC_FALSE;
  } else
    ret = OFC_TRUE;

  return (ret);
}

static OFC_BOOL OfcFSLinuxWriteFile(OFC_HANDLE hFile,
				    OFC_LPCVOID lpBuffer,
				    OFC_DWORD nNumberOfBytesToWrite,
				    OFC_LPDWORD lpNumberOfBytesWritten,
				    OFC_HANDLE hOverlapped)
{
  OFC_BOOL ret;
  ssize_t status;
  OFC_FS_LINUX_CONTEXT *context;
  OFC_FSLINUX_OVERLAPPED *Overlapped;

#if defined(OFC_PERF_STATS)
  perf_rt_start(prt_write);
#endif
  ret = OFC_FALSE;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL || context->backup) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    Overlapped = OFC_NULL;
    if (hOverlapped != OFC_HANDLE_NULL) {
      Overlapped = ofc_handle_lock(hOverlapped);
    }

    if (Overlapped != OFC_NULL) {
#if defined(OFC_PERF_STATS)
      perf_request_start(g_measurement, pqueue_write);
#endif
      ofc_event_reset(Overlapped->hEvent);
      Overlapped->fd = context->fd;
      Overlapped->lpBuffer = lpBuffer;
      Overlapped->nNumberOfBytes = nNumberOfBytesToWrite;
      Overlapped->opcode = OFC_FSLINUX_WRITE;

      ofc_trace ("aio_write 0x%08x\n",
		 (OFC_INT) Overlapped->offset);

      ofc_event_set(Overlapped->hBusy);

      ofc_thread_set_variable(OfcLastError, (OFC_DWORD_PTR)
			      TranslateError(EINPROGRESS));

      ofc_handle_unlock(hOverlapped);
      ret = OFC_FALSE;
    } else {
#if defined(OFC_PERF_STATS)
      perf_request_start(g_measurement, pqueue_write);
#endif
      status = write(context->fd, lpBuffer, nNumberOfBytesToWrite);

      if (status >= 0) {
#if defined(OFC_PERF_STATS)
        perf_request_stop(g_measurement, pqueue_write, status);
#endif
	if (lpNumberOfBytesWritten != OFC_NULL)
	  *lpNumberOfBytesWritten = (OFC_DWORD) status;
	ret = OFC_TRUE;
      } else {
#if defined(OFC_PERF_STATS)
        perf_request_stop(g_measurement, pqueue_write, 0);
#endif
	ofc_thread_set_variable(OfcLastError,
				(OFC_DWORD_PTR) TranslateError(errno));
	ret = OFC_FALSE;
      }
    }
  }

  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);

#if defined(OFC_PERF_STATS)
  perf_rt_stop(prt_write);
#endif
  return (ret);
}

static OFC_BOOL OfcFSLinuxReadFile(OFC_HANDLE hFile,
				   OFC_LPVOID lpBuffer,
				   OFC_DWORD nNumberOfBytesToRead,
				   OFC_LPDWORD lpNumberOfBytesRead,
				   OFC_HANDLE hOverlapped)
{
  OFC_BOOL ret;
  ssize_t status;
  OFC_FS_LINUX_CONTEXT *context;
  OFC_FSLINUX_OVERLAPPED *Overlapped;

#if defined(OFC_PERF_STATS)
  perf_rt_start(prt_read);
#endif

  ret = OFC_FALSE;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL || context->backup) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    Overlapped = OFC_NULL;
    if (hOverlapped != OFC_HANDLE_NULL)
      Overlapped = ofc_handle_lock(hOverlapped);

    if (Overlapped != OFC_NULL) {
#if defined(OFC_PERF_STATS)
      perf_request_start(g_measurement, pqueue_read);
#endif
      /*
       * Offset should already be set
       */
      ofc_event_reset(Overlapped->hEvent);
      Overlapped->fd = context->fd;
      Overlapped->lpBuffer = lpBuffer;
      Overlapped->nNumberOfBytes = nNumberOfBytesToRead;
      Overlapped->opcode = OFC_FSLINUX_READ;

      ofc_trace ("aio_read 0x%08x\n",
		 (OFC_INT) Overlapped->offset);

      ofc_event_set(Overlapped->hBusy);

      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(EINPROGRESS));

      ofc_handle_unlock(hOverlapped);
      ret = OFC_FALSE;
    } else {
#if defined(OFC_PERF_STATS)
      perf_request_start(g_measurement, pqueue_read);
#endif
      status = read(context->fd, lpBuffer, nNumberOfBytesToRead);

      if (status > 0) {
#if defined(OFC_PERF_STATS)
        perf_request_stop(g_measurement, pqueue_read, status);
#endif
	if (lpNumberOfBytesRead != OFC_NULL)
	  *lpNumberOfBytesRead = (OFC_DWORD) status;
	ret = OFC_TRUE;
      } else {
#if defined(OFC_PERF_STATS)
        perf_request_stop(g_measurement, pqueue_read, 0);
#endif
	ret = OFC_FALSE;
	if (status == 0)
	  ofc_thread_set_variable(OfcLastError, (OFC_DWORD_PTR)
				  OFC_ERROR_HANDLE_EOF);
	else
	  ofc_thread_set_variable(OfcLastError, (OFC_DWORD_PTR)
				  TranslateError(errno));
      }
    }
  }

  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);

#if defined(OFC_PERF_STATS)
  perf_rt_stop(prt_read);
#endif
  return (ret);
}

static OFC_BOOL OfcFSLinuxCloseHandle(OFC_HANDLE hFile)
{
  OFC_BOOL ret;
  int status;
  OFC_FS_LINUX_CONTEXT *context;

  ret = OFC_FALSE;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    if (context->fd == -1 || context->backup)
      status = 0;
    else
      status = close(context->fd);

    if (status >= 0) {
      if (context->deleteOnClose) {
	rmdir(context->name);
	unlink(context->name);
      }

      ofc_handle_destroy(hFile);
      ofc_free(context->name);
      ofc_free(context);
      ret = OFC_TRUE;
    } else {
      ret = OFC_FALSE;
      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(errno));
    }
  }
  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);
      
  return (ret);
}

static OFC_BOOL OfcFSLinuxDeleteFile(OFC_LPCTSTR lpFileName)
{
  OFC_BOOL ret;
  int status;
  OFC_CHAR *asciiName;


  ret = OFC_TRUE;
  asciiName = FilePath2LinuxPath(lpFileName);

  status = unlink(asciiName);
  ofc_free(asciiName);

  if (status < 0) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
    ret = OFC_FALSE;
  }

  return (ret);
}

static OFC_BOOL OfcFSLinuxRemoveDirectory(OFC_LPCTSTR lpPathName)
{
  OFC_BOOL ret;
  int status;
  OFC_CHAR *asciiName;

  ret = OFC_TRUE;
  asciiName = FilePath2LinuxPath(lpPathName);
  status = rmdir(asciiName);

  ofc_free(asciiName);
  if (status < 0) {
    ret = OFC_FALSE;
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
  }

  return (ret);
}

static OFC_BOOL GetWin32FindFileData(OFC_CHAR *asciiName,
                                     OFC_CCHAR *dName,
                                     OFC_LPWIN32_FIND_DATAW lpFindFileData)
{
  struct stat sb;
  int status;
  OFC_BOOL ret;
  OFC_TCHAR *tcharName;

  ret = OFC_TRUE;
  status = stat(asciiName, &sb);
  if (status == -1) {
    /*
     * See if it's a link.  If so, we still want to show it.  The reason
     * we use stat rather then lstat initially is we do want the
     * target of the link.  We only want to revert to the link when
     * the target returns an error.
     */
    status = lstat(asciiName, &sb);
  }

  lpFindFileData->dwFileAttributes = 0 ;
  epoch_time_to_file_time(0, 0, &lpFindFileData->ftCreateTime) ;
  epoch_time_to_file_time(0, 0, &lpFindFileData->ftLastAccessTime) ;
  epoch_time_to_file_time(0, 0, &lpFindFileData->ftLastWriteTime) ;
  lpFindFileData->nFileSizeHigh = 0 ;
  lpFindFileData->nFileSizeLow = 0 ;
  tcharName = ofc_cstr2tstr (dName) ;
  ofc_tstrncpy (lpFindFileData->cFileName, tcharName, OFC_MAX_PATH) ;
  ofc_free(tcharName) ;

  lpFindFileData->cAlternateFileName[0] = TCHAR_EOS ;

  if (status >= 0) {
    /*
     * We do not support hidden files or System Files or Archive Files
     * or temporary or sparse or compressed,or offline, or encrypted,
     * or virtual
     */
    if (sb.st_mode & S_IFDIR)
      lpFindFileData->dwFileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY;
    if (lpFindFileData->dwFileAttributes == 0)
      lpFindFileData->dwFileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL;
    if (dName[0] == '.')
      lpFindFileData->dwFileAttributes |= OFC_FILE_ATTRIBUTE_HIDDEN;
    /*
     * Next is create time
     */
    epoch_time_to_file_time(sb.st_mtime, sb.st_mtimensec,
			    &lpFindFileData->ftCreateTime);
    epoch_time_to_file_time(sb.st_atime, sb.st_atimensec,
			    &lpFindFileData->ftLastAccessTime);
    epoch_time_to_file_time(sb.st_ctime, sb.st_ctimensec,
			    &lpFindFileData->ftLastWriteTime);
#if defined(USE_FILE_OFFSET64)
    lpFindFileData->nFileSizeHigh = sb.st_size >> 32 ;
    lpFindFileData->nFileSizeLow = sb.st_size & 0xFFFFFFFF ;
#else
    lpFindFileData->nFileSizeHigh = 0 ;
    lpFindFileData->nFileSizeLow = sb.st_size ;
#endif
  } else {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
    ret = OFC_FALSE;
  }

  return (ret);
}

static OFC_BOOL
GetWin32FileAttributeData(OFC_CHAR *asciiName,
                          OFC_WIN32_FILE_ATTRIBUTE_DATA *fadata)
{
  OFC_BOOL ret;
  struct stat sb;
  int status;

  ret = OFC_FALSE;

  status = stat(asciiName, &sb);
  if (status == -1) {
    /*
     * See if it's a link.  If so, we still want to show it.  The reason
     * we use stat rather then lstat initially is we do want the
     * target of the link.  We only want to revert to the link when
     * the target returns an error.
     */
    status = lstat(asciiName, &sb);
  }

  if (status >= 0) {
    fadata->dwFileAttributes = 0;
    /*
     * We do not support hidden files or System Files or Archive Files
     * or temporary or sparse or compressed,or offline, or encrypted,
     * or virtual
     */
    if (sb.st_mode & S_IFDIR) {
      fadata->dwFileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY;
    }
    if (fadata->dwFileAttributes == 0)
      fadata->dwFileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL;
    /*
     * Next is create time
     * Can't believe we don't have a create time, but it looks like we
     * only have last access, modification, and status change
     */
    epoch_time_to_file_time(sb.st_mtime, sb.st_mtimensec,
			    &fadata->ftCreateTime);
    epoch_time_to_file_time(sb.st_atime, sb.st_atimensec,
			    &fadata->ftLastAccessTime);
    epoch_time_to_file_time(sb.st_ctime, sb.st_ctimensec,
			    &fadata->ftLastWriteTime);
#if defined(__USE_FILE_OFFSET64)
    fadata->nFileSizeHigh = sb.st_size >> 32 ;
    fadata->nFileSizeLow = sb.st_size & 0xFFFFFFFF ;
#else
    fadata->nFileSizeHigh = 0 ;
    fadata->nFileSizeLow = sb.st_size ;
#endif
    ret = OFC_TRUE;
  } else {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
  }
  return (ret);
}

static OFC_BOOL GetWin32FileBasicInfo(int fd,
                                      OFC_CHAR *name,
                                      OFC_FILE_BASIC_INFO *lpFileInformation)
{
  OFC_BOOL ret;
  OFC_FILETIME filetime;
  struct stat sb;
  int status;

  ret = OFC_FALSE;

  if (fd == -1) {
    status = stat(name, &sb);
    if (status == -1) {
      /*
       * See if it's a link.  If so, we still want to show it.  The reason
       * we use stat rather then lstat initially is we do want the
       * target of the link.  We only want to revert to the link when
       * the target returns an error.
       */
      status = lstat(name, &sb);
    }
  } else {
    status = fstat(fd, &sb);
  }

  if (status >= 0) {
    epoch_time_to_file_time(sb.st_mtime, sb.st_mtimensec, &filetime);
#if defined(OFC_64BIT_INTEGER)
    lpFileInformation->CreationTime =
      ((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) |
      (OFC_LARGE_INTEGER) filetime.dwLowDateTime;
    lpFileInformation->LastWriteTime =
      ((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) |
      (OFC_LARGE_INTEGER) filetime.dwLowDateTime;
#else
    lpFileInformation->CreationTime.high = filetime.dwHighDateTime ;
    lpFileInformation->CreationTime.low = filetime.dwLowDateTime ;
    lpFileInformation->LastWriteTime.high = filetime.dwHighDateTime ;
    lpFileInformation->LastWriteTime.low = filetime.dwLowDateTime ;
#endif
    epoch_time_to_file_time(sb.st_atime, sb.st_atimensec, &filetime);
#if defined(OFC_64BIT_INTEGER)
    lpFileInformation->LastAccessTime =
      ((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) |
      (OFC_LARGE_INTEGER) filetime.dwLowDateTime;
#else
    lpFileInformation->LastAccessTime.high = filetime.dwHighDateTime ;
    lpFileInformation->LastAccessTime.low = filetime.dwLowDateTime ;
#endif
    epoch_time_to_file_time(sb.st_ctime, sb.st_ctimensec, &filetime);
#if defined(OFC_64BIT_INTEGER)
    lpFileInformation->ChangeTime =
      ((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) |
      filetime.dwLowDateTime;
#else
    lpFileInformation->ChangeTime.high = filetime.dwHighDateTime ;
    lpFileInformation->ChangeTime.low = filetime.dwLowDateTime ;
#endif
    lpFileInformation->FileAttributes = 0;
    /*
     * We do not support hidden files or System Files or Archive Files
     * or temporary or sparse or compressed,or offline, or encrypted,
     * or virtual
     */
    if (sb.st_mode & S_IFDIR)
      lpFileInformation->FileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY;
    if (lpFileInformation->FileAttributes == 0)
      lpFileInformation->FileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL;
    ret = OFC_TRUE;
  } else {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
  }

  return (ret);
}

static OFC_BOOL
GetWin32FileStandardInfo(int fd,
                         OFC_CHAR *name,
                         OFC_FILE_STANDARD_INFO *lpFileInformation,
                         OFC_BOOL delete_pending)
{
  OFC_BOOL ret;
  struct stat sb;
  int status;

  ret = OFC_FALSE;

  if (fd == -1) {
    status = stat(name, &sb);
    if (status == -1) {
      /*
       * See if it's a link.  If so, we still want to show it.  The reason
       * we use stat rather then lstat initially is we do want the
       * target of the link.  We only want to revert to the link when
       * the target returns an error.
       */
      status = lstat(name, &sb);
    }
  } else {
    status = fstat(fd, &sb);
  }

  if (status >= 0) {
#if defined(OFC_64BIT_INTEGER)
    lpFileInformation->AllocationSize =
      sb.st_blocks * OFC_FS_LINUX_BLOCK_SIZE;
    lpFileInformation->EndOfFile = sb.st_size;
#else
    lpFileInformation->AllocationSize.low =
      sb.st_blocks * OFC_FS_LINUX_BLOCK_SIZE ;
    lpFileInformation->EndOfFile.low = sb.st_size ;
    lpFileInformation->AllocationSize.high = 0 ;
    lpFileInformation->EndOfFile.high = 0 ;
#endif
    lpFileInformation->NumberOfLinks = sb.st_nlink;
    lpFileInformation->DeletePending = delete_pending;
    lpFileInformation->Directory = OFC_FALSE;
    if (sb.st_mode & S_IFDIR)
      lpFileInformation->Directory = OFC_TRUE;
    ret = OFC_TRUE;
  } else {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
  }

  return (ret);
}

static OFC_BOOL GetWin32FileNameInfo(int fd,
                                     OFC_CHAR *name,
                                     OFC_FILE_NAME_INFO *lpFileInformation,
                                     OFC_DWORD dwBufferSize)
{
  OFC_TCHAR *tcharName;

  tcharName = ofc_cstr2tstr(name);
  lpFileInformation->FileNameLength = (OFC_DWORD) ofc_tstrlen(tcharName) *
    sizeof(OFC_TCHAR);
  ofc_memcpy(lpFileInformation->FileName, tcharName,
	     OFC_MIN (dwBufferSize - sizeof(OFC_DWORD),
		      lpFileInformation->FileNameLength *
		      sizeof(OFC_TCHAR)));
  ofc_free(tcharName);
  return (OFC_TRUE);
}


static OFC_BOOL
GetWin32FileIdBothDirInfo(int fd,
                          OFC_CHAR *name,
                          OFC_FILE_ID_BOTH_DIR_INFO *lpFileInfo,
                          OFC_DWORD dwBufferSize)
{
  OFC_BOOL ret;
  struct stat sb;
  int status;
  OFC_TCHAR *tcharName;
  OFC_FILETIME filetime;

  ret = OFC_FALSE;

  status = fstat (fd, &sb) ;

  if (status >= 0)
    {
      lpFileInfo->NextEntryOffset = 0;
      /*
       * This isn't right, but it's probably the closest we can do
       */
      lpFileInfo->FileIndex = 0;
      epoch_time_to_file_time(sb.st_mtime, sb.st_mtimensec,
			      &filetime);
#if defined(OFC_64BIT_INTEGER)
      lpFileInfo->CreationTime =
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) |
	filetime.dwLowDateTime;
      lpFileInfo->LastWriteTime =
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) |
	filetime.dwLowDateTime;
#else
      lpFileInfo->CreationTime.high = filetime.dwHighDateTime ;
      lpFileInfo->CreationTime.low = filetime.dwLowDateTime ;
      lpFileInfo->LastWriteTime.high = filetime.dwHighDateTime ;
      lpFileInfo->LastWriteTime.low = filetime.dwLowDateTime ;
#endif
      epoch_time_to_file_time(sb.st_atime, sb.st_atimensec, &filetime);
#if defined(OFC_64BIT_INTEGER)
      lpFileInfo->LastAccessTime =
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) |
	filetime.dwLowDateTime;
#else
      lpFileInfo->LastAccessTime.high = filetime.dwHighDateTime ;
      lpFileInfo->LastAccessTime.low = filetime.dwLowDateTime ;
#endif
      epoch_time_to_file_time(sb.st_ctime,
			      sb.st_ctimensec, &filetime);
#if defined(OFC_64BIT_INTEGER)
      lpFileInfo->ChangeTime =
	((OFC_LARGE_INTEGER) filetime.dwHighDateTime << 32) |
	filetime.dwLowDateTime;
      lpFileInfo->EndOfFile = sb.st_size;
      lpFileInfo->AllocationSize =
	sb.st_blocks * OFC_FS_LINUX_BLOCK_SIZE;
#else
      lpFileInfo->ChangeTime.high = filetime.dwHighDateTime ;
      lpFileInfo->ChangeTime.low = filetime.dwLowDateTime ;
      lpFileInfo->EndOfFile.low = sb.st_size ;
      lpFileInfo->EndOfFile.high = 0 ;
      lpFileInfo->AllocationSize.low =
	sb.st_blocks * OFC_FS_LINUX_BLOCK_SIZE ;
      lpFileInfo->AllocationSize.high = 0 ;
#endif
      lpFileInfo->FileAttributes = 0;
      /*
       * We do not support hidden files or System Files or Archive Files
       * or temporary or sparse or compressed,or offline, or encrypted,
       * or virtual
       */
      if (sb.st_mode & S_IFDIR)
	lpFileInfo->FileAttributes |= OFC_FILE_ATTRIBUTE_DIRECTORY;
      if (lpFileInfo->FileAttributes == 0)
	lpFileInfo->FileAttributes |= OFC_FILE_ATTRIBUTE_NORMAL;

      tcharName = ofc_cstr2tstr(name);
      lpFileInfo->FileNameLength = ofc_tstrlen(tcharName) ;
      lpFileInfo->EaSize = 0;
      lpFileInfo->ShortNameLength = 0;
      lpFileInfo->ShortName[0] = TCHAR_EOS;
      lpFileInfo->FileId = 0;
      ofc_memcpy (lpFileInfo->FileName, tcharName,
		  OFC_MIN (dwBufferSize - 
			   sizeof (OFC_FILE_ID_BOTH_DIR_INFO) - 
			   sizeof (OFC_TCHAR),
			   lpFileInfo->FileNameLength *
			   sizeof (OFC_TCHAR))) ;
      ofc_free(tcharName);
      ret = OFC_TRUE;
    } else {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
  }

  return (ret);
}

static OFC_INT read_dir (OFC_CHAR *pattern, DIR * dir, 
			 struct dirent **pdirent)
{
  OFC_BOOL done ;
  OFC_INT ret ;

  done = OFC_FALSE ;

  errno = 0 ;
  for (*pdirent = readdir (dir) ; !done ; )
    {
      if (*pdirent == OFC_NULL)
	{
	  if (errno == EAGAIN)
	    {
	      sleep (1) ;
	      errno = 0 ;
	      *pdirent = readdir (dir) ;
	    }
	  else
	    {
	      done = OFC_TRUE ;
	    }
	}
      else
	{
	  if (ofc_file_match (pattern, (*pdirent)->d_name,
			      OFC_FILE_MATCH_PATHNAME |
			      OFC_FILE_MATCH_CASEFOLD)) 
	    done = OFC_TRUE ;
	  else
	    {
	      errno = 0 ;
	      *pdirent = readdir (dir) ;
	    }
	}
    }

  return (*pdirent == NULL);
}

static OFC_VOID free_dir_context (OFC_FS_LINUX_CONTEXT *context)
{
  ofc_free(context->name) ;
  if (context->pattern != NULL)
    ofc_free(context->pattern) ;
  ofc_free(context) ;
}

static OFC_HANDLE
OfcFSLinuxFindFirstFile(OFC_LPCTSTR lpFileName,
			OFC_LPWIN32_FIND_DATAW lpFindFileData,
			OFC_BOOL *more)
{
  OFC_HANDLE hRet;
  OFC_FS_LINUX_CONTEXT *context;
  OFC_CHAR *asciiName;
  OFC_TCHAR *tcharName;
  struct dirent *dirent;
  OFC_CHAR *pathname;
  OFC_SIZET len;
  OFC_PATH *path;
  OFC_LPTSTR cursor;
  OFC_LPCTSTR filename;

  context = ofc_malloc(sizeof(OFC_FS_LINUX_CONTEXT));

  hRet = OFC_INVALID_HANDLE_VALUE;
  if (context != OFC_NULL) {
    context->pattern = OFC_NULL;

    path = ofc_path_createW(lpFileName);
    filename = ofc_path_filename(path);
    if (filename != OFC_NULL) {
      context->pattern = ofc_tstr2cstr(filename);
      ofc_path_free_filename(path);
    }

    ofc_path_set_type(path, OFC_FST_LINUX);
    len = 0;
    len = ofc_path_printW(path, NULL, &len) + 1;
    tcharName = ofc_malloc(len * sizeof(OFC_TCHAR));
    cursor = tcharName;
    ofc_path_printW(path, &cursor, &len);
    ofc_path_delete(path);

    asciiName = FilePath2LinuxPath(tcharName);
    ofc_free(tcharName);
    context->name = ofc_strdup(asciiName);
    context->dir = opendir(asciiName);
    ofc_free(asciiName);
    if (context->dir != NULL) {
      context->nextRet =
	read_dir (context->pattern, context->dir, &dirent) ;
      if (dirent == NULL) {
	closedir(context->dir);
	context->dir = NULL;
      } else {
	/*
	 * Let's return the info
	 */
	len = ofc_strlen(context->name) + ofc_strlen(dirent->d_name);
	pathname = ofc_malloc(len + 2);
	ofc_snprintf(pathname, len + 2, "%s/%s",
		     context->name, dirent->d_name);
	GetWin32FindFileData(pathname, dirent->d_name, lpFindFileData);
	ofc_free(pathname);

	*more = OFC_FALSE;

	context->nextRet = read_dir (context->pattern, context->dir, 
				     &context->nextDirent);
	if (context->nextDirent != NULL)
	  *more = OFC_TRUE;
      }
    }

    if (context->dir == NULL) {
      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(errno));
      free_dir_context(context) ;
    } else
      hRet = ofc_handle_create(OFC_HANDLE_FSLINUX_FILE, context);
  }

  return (hRet);
}

static OFC_BOOL
OfcFSLinuxFindNextFile(OFC_HANDLE hFindFile,
		       OFC_LPWIN32_FIND_DATAW lpFindFileData,
		       OFC_BOOL *more)
{
  struct dirent *dirent;
  OFC_FS_LINUX_CONTEXT *context;
  OFC_BOOL ret;
  OFC_CHAR *pathname;
  OFC_SIZET len;

  ret = OFC_FALSE;
  *more = OFC_FALSE;
  context = ofc_handle_lock(hFindFile);

  if (context == OFC_NULL) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    if (context->nextRet == 0 && context->dir != OFC_NULL)
      {
	ret = OFC_TRUE;
	len = ofc_strlen(context->name) +
	  ofc_strlen(context->nextDirent->d_name);
	pathname = ofc_malloc(len + 2);
	ofc_snprintf(pathname, len + 2, "%s/%s",
		     context->name,
		     context->nextDirent->d_name);
	ret = GetWin32FindFileData(pathname, context->nextDirent->d_name,
				   lpFindFileData);
	ofc_free(pathname);

	context->nextRet = 
	  read_dir (context->pattern, context->dir, &context->nextDirent);

	if (context->nextDirent != NULL)
	  {
	    *more = OFC_TRUE;
	  }
	else
	  ofc_thread_set_variable(OfcLastError,
				  OFC_ERROR_NO_MORE_FILES);
      }
    else
      {
	if (context->nextDirent == OFC_NULL)
	  ofc_thread_set_variable(OfcLastError,
				  OFC_ERROR_NO_MORE_FILES);
	else
	  ofc_thread_set_variable(OfcLastError,
				  (OFC_DWORD_PTR) TranslateError(errno));
      }
	  
    ofc_handle_unlock(hFindFile);
  }

  return (ret);
}

static OFC_BOOL OfcFSLinuxFindClose(OFC_HANDLE hFindFile)
{
  OFC_BOOL ret;
  OFC_FS_LINUX_CONTEXT *context;
  int status;

  ret = OFC_FALSE;
  context = ofc_handle_lock(hFindFile);

  if (context == OFC_NULL) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    status = 0 ;
    if (context->dir != OFC_NULL)
      {
	status = closedir (context->dir) ;
      }

    if (status == 0) {
      ret = OFC_TRUE;
      ofc_handle_destroy(hFindFile);
      free_dir_context(context);
    } else
      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(errno));

    ofc_handle_unlock(hFindFile);
  }

  return (ret);
}

static OFC_BOOL OfcFSLinuxFlushFileBuffers(OFC_HANDLE hFile)
{
  /*
   * No flush needed
   */
  return (OFC_TRUE);
}

static OFC_BOOL
OfcFSLinuxGetFileAttributesEx(OFC_LPCTSTR lpFileName,
			      OFC_GET_FILEEX_INFO_LEVELS fInfoLevelId,
			      OFC_LPVOID lpFileInformation)
{
  OFC_BOOL ret;
  OFC_CHAR *asciiName;

  ret = OFC_FALSE;
  /*
   * This is the only one we support
   */
  if (fInfoLevelId == OfcGetFileExInfoStandard) {
    asciiName = FilePath2LinuxPath(lpFileName);
    ret = GetWin32FileAttributeData(asciiName, lpFileInformation);
    ofc_free(asciiName);
  }
  return (ret);
}

static OFC_BOOL
OfcFSLinuxGetFileInformationByHandleEx
(OFC_HANDLE hFile,
 OFC_FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
 OFC_LPVOID lpFileInformation,
 OFC_DWORD dwBufferSize)
{
  OFC_BOOL ret;
  OFC_FS_LINUX_CONTEXT *context;

  ret = OFC_FALSE;

  context = ofc_handle_lock(hFile);
  if (context == OFC_NULL) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    switch (FileInformationClass) {
    case OfcFileBasicInfo:
      if (dwBufferSize >= sizeof(OFC_FILE_BASIC_INFO)) {
	ret = GetWin32FileBasicInfo(context->fd,
				    context->name,
				    lpFileInformation);
      }
      break;

    case OfcFileStandardInfo:
      if (dwBufferSize >= sizeof(OFC_FILE_STANDARD_INFO)) {
	ret = GetWin32FileStandardInfo(context->fd,
				       context->name,
				       lpFileInformation,
				       context->deleteOnClose);
      }
      break;

    case OfcFileNameInfo:
      if (dwBufferSize >= sizeof(OFC_FILE_NAME_INFO) - sizeof(OFC_WCHAR)) {
	ret = GetWin32FileNameInfo(context->fd, context->name,
				   lpFileInformation,
				   dwBufferSize);
      }
      break;

    case OfcFileEaInfo:
      if (dwBufferSize >= sizeof(OFC_FILE_EA_INFO))
        {
          OFC_FILE_EA_INFO *lpFileEaInfo =
            (OFC_FILE_EA_INFO *) lpFileInformation;
          lpFileEaInfo->EaSize = 0;
          ret = OFC_TRUE;
        }
      break;

    case OfcFileEndOfFileInfo:
    case OfcFileRenameInfo:
    case OfcFileDispositionInfo:
    case OfcFileAllocationInfo:
    case OfcFileInfoStandard:
      /*
       * These are for sets. They don't apply for get
       */
      break;

    default:
    case OfcFileStreamInfo:
    case OfcFileCompressionInfo:
    case OfcFileAttributeTagInfo:
    case OfcFileIdBothDirectoryRestartInfo:
      /*
       * These are not supported
       */
      break;

    case OfcFileIdBothDirectoryInfo:
      if (dwBufferSize >= sizeof(OFC_FILE_ID_BOTH_DIR_INFO) -
	  sizeof(OFC_WCHAR)) {
	ret = GetWin32FileIdBothDirInfo(context->fd, context->name,
					lpFileInformation,
					dwBufferSize);
      }
      break;

    case OfcFileAllInfo:
      if (dwBufferSize >= sizeof(OFC_FILE_ALL_INFO) -
	  sizeof(OFC_WCHAR)) {
	OFC_FILE_ALL_INFO *lpAllInformation =
	  (OFC_FILE_ALL_INFO *) lpFileInformation;

	ret = GetWin32FileBasicInfo(context->fd,
				    context->name,
				    &lpAllInformation->BasicInfo);
	if (ret) {
	  ret = GetWin32FileStandardInfo(context->fd,
					 context->name,
					 &lpAllInformation->StandardInfo,
					 context->deleteOnClose);
	}
	if (ret) {
	  ret = OFC_TRUE ;
	  lpAllInformation->InternalInfo.IndexNumber = 0L ;
	}
	if (ret) {
	  lpAllInformation->EAInfo.EaSize = 0;
	  if (lpAllInformation->BasicInfo.FileAttributes &
	      OFC_FILE_ATTRIBUTE_DIRECTORY) {
	    lpAllInformation->AccessInfo.AccessFlags =
	      OFC_FILE_LIST_DIRECTORY |
	      OFC_FILE_ADD_FILE |
	      OFC_FILE_ADD_SUBDIRECTORY |
	      OFC_FILE_DELETE_CHILD |
	      OFC_FILE_READ_ATTRIBUTES |
	      OFC_FILE_WRITE_ATTRIBUTES |
	      OFC_DELETE;
	  } else {
	    lpAllInformation->AccessInfo.AccessFlags =
	      OFC_FILE_READ_DATA |
	      OFC_FILE_WRITE_DATA |
	      OFC_FILE_APPEND_DATA |
	      OFC_FILE_EXECUTE |
	      OFC_FILE_READ_ATTRIBUTES |
	      OFC_FILE_WRITE_ATTRIBUTES |
	      OFC_DELETE;
	  }
	  lpAllInformation->PositionInfo.CurrentByteOffset = 0;
	  lpAllInformation->ModeInfo.Mode = 0;
	  lpAllInformation->AlignmentInfo.AlignmentRequirement = 0;
	}
	if (ret) {
	  ret = GetWin32FileNameInfo(context->fd,
				     context->name,
				     &lpAllInformation->NameInfo,
				     dwBufferSize -
				     sizeof(OFC_FILE_ALL_INFO));
	}
      }
      break;
    }
    ofc_handle_unlock(hFile);
  }

  return (ret);
}

static OFC_BOOL OfcFSLinuxMoveFile(OFC_LPCTSTR lpExistingFileName,
				   OFC_LPCTSTR lpNewFileName)
{
  OFC_BOOL ret;
  int status;

  OFC_CHAR *asciiExisting;
  OFC_CHAR *asciiNew;

  ret = OFC_TRUE;
  asciiExisting = FilePath2LinuxPath(lpExistingFileName);
  asciiNew = FilePath2LinuxPath(lpNewFileName);

  status = rename(asciiExisting, asciiNew);
  ofc_free(asciiExisting);
  ofc_free(asciiNew);

  if (status < 0) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));
    ret = OFC_FALSE;
  }

  return (ret);
}

OFC_HANDLE OfcFSLinuxGetOverlappedEvent(OFC_HANDLE hOverlapped)
{
  OFC_FSLINUX_OVERLAPPED *Overlapped;
  OFC_HANDLE hRet;

  hRet = OFC_HANDLE_NULL;
  Overlapped = ofc_handle_lock(hOverlapped);
  if (Overlapped != OFC_NULL) {
    hRet = Overlapped->hEvent;
    ofc_handle_unlock(hOverlapped);
  }
  return (hRet);
}

static OFC_HANDLE OfcFSLinuxCreateOverlapped(OFC_VOID)
{
  OFC_FSLINUX_OVERLAPPED *Overlapped;
  OFC_HANDLE hRet;

  hRet = OFC_HANDLE_NULL;

  hRet = (OFC_HANDLE) ofc_dequeue(OfcFSLinuxAIOFreeQ);
  if (hRet == OFC_HANDLE_NULL) {
    Overlapped = ofc_malloc(sizeof(OFC_FSLINUX_OVERLAPPED));
    if (Overlapped != OFC_NULL) {
      hRet = ofc_handle_create(OFC_HANDLE_FSLINUX_OVERLAPPED,
			       Overlapped);
      Overlapped->offset = 0;
      Overlapped->hEvent = ofc_event_create(OFC_EVENT_MANUAL);
      Overlapped->hBusy = ofc_event_create(OFC_EVENT_AUTO);

      Overlapped->hThread = ofc_thread_create(&OfcFSLinuxAIOThread,
					      OFC_THREAD_AIO,
					      g_instance++,
					      Overlapped,
					      OFC_THREAD_JOIN,
					      OFC_HANDLE_NULL);
    }
  }

  if (hRet != OFC_HANDLE_NULL) {
    Overlapped = ofc_handle_lock(hRet);
    if (Overlapped != OFC_NULL) {
      Overlapped->Errno = 0;
      ofc_handle_unlock(hRet);
    }
  }
  return (hRet);
}

OFC_VOID OfcFSLinuxDestroyOverlapped(OFC_HANDLE hOverlapped)
{
  ofc_enqueue(OfcFSLinuxAIOFreeQ, (OFC_VOID *) hOverlapped);
}

OFC_VOID OfcFSLinuxSetOverlappedOffset(OFC_HANDLE hOverlapped,
				       OFC_OFFT offset)
{
  OFC_FSLINUX_OVERLAPPED *Overlapped;

  Overlapped = ofc_handle_lock(hOverlapped);
  if (Overlapped != OFC_NULL) {
    Overlapped->offset = offset;
    ofc_handle_unlock(hOverlapped);
  }
}

static OFC_BOOL
OfcFSLinuxGetOverlappedResult(OFC_HANDLE hFile,
			      OFC_HANDLE hOverlapped,
			      OFC_LPDWORD lpNumberOfBytesTransferred,
			      OFC_BOOL bWait)
{
  OFC_FSLINUX_OVERLAPPED *Overlapped;
  OFC_FS_LINUX_CONTEXT *context;
  OFC_BOOL ret;
#if defined(OFC_PERF_STATS)
  struct perf_rt *prt_overlapped;
  struct perf_queue *pqueue_overlapped;
#endif

  ret = OFC_FALSE;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL || context->backup) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    Overlapped = ofc_handle_lock(hOverlapped);
    if (Overlapped != OFC_NULL) {
#if defined(OFC_PERF_STATS)
      if (Overlapped->opcode == OFC_FSLINUX_READ)
        {
          prt_overlapped = prt_read;
          pqueue_overlapped = pqueue_read;
        }
      else
        {
          prt_overlapped = prt_write;
          pqueue_overlapped = pqueue_write;
        }
      perf_rt_start(prt_overlapped);
#endif

      if (bWait)
	ofc_event_wait(Overlapped->hEvent);

      if (ofc_event_test(Overlapped->hEvent)) {
	if (Overlapped->dwResult < 0) {
	  ofc_thread_set_variable(OfcLastError,
				  (OFC_DWORD_PTR)
				  TranslateError(Overlapped->Errno));
#if defined(OFC_PERF_STATS)
          perf_request_stop(g_measurement, pqueue_overlapped, 0);
#endif
	} else {
#if defined(OFC_PERF_STATS)
          perf_request_stop(g_measurement, pqueue_overlapped, Overlapped->dwResult);
#endif
	  *lpNumberOfBytesTransferred = Overlapped->dwResult;
	  ret = OFC_TRUE;
	}
      } else {
	ofc_thread_set_variable(OfcLastError,
				(OFC_DWORD_PTR)
				TranslateError(EINPROGRESS));
      }
#if defined(OFC_PERF_STATS)
      perf_rt_stop(prt_overlapped);
#endif
      ofc_handle_unlock(hOverlapped);
    }
  }

  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);

  return (ret);
}

static OFC_BOOL OfcFSLinuxSetEndOfFile(OFC_HANDLE hFile)
{
  OFC_BOOL ret;
  OFC_FS_LINUX_CONTEXT *context;
  off_t offset;
  int status;

  ret = OFC_FALSE;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL || context->backup) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    /*
     * Get current offset
     */
    offset = lseek(context->fd, 0, SEEK_CUR);
    if (offset >= 0) {
      status = ftruncate(context->fd, offset);
      if (status == 0)
	ret = OFC_TRUE;
      else
	ofc_thread_set_variable(OfcLastError,
				(OFC_DWORD_PTR) TranslateError(errno));
    } else
      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(errno));
  }

  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);

  return (ret);
}

static OFC_BOOL OfcFSLinuxSetFileAttributes(OFC_LPCTSTR lpFileName,
					    OFC_DWORD dwFileAttributes)
{
  OFC_BOOL ret;

  /*
   * We can't set file attributes on Linux
   */
  ret = OFC_TRUE;

  return (ret);
}

static OFC_BOOL
OfcFSLinuxSetFileInformationByHandle(OFC_HANDLE hFile,
				     OFC_FILE_INFO_BY_HANDLE_CLASS
				     FileInformationClass,
				     OFC_LPVOID lpFileInformation,
				     OFC_DWORD dwBufferSize)
{
  OFC_BOOL ret;
  OFC_FS_LINUX_CONTEXT *context;

  ret = OFC_FALSE;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL || context->backup) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    switch (FileInformationClass) {
    case OfcFileBasicInfo:
      ret = OFC_TRUE;
      break;

    case OfcFileAllocationInfo:
    default:
      ofc_thread_set_variable(OfcLastError,
			      OFC_ERROR_NOT_SUPPORTED);
      break;

    case OfcFileRenameInfo:
      {
	OFC_FILE_RENAME_INFO *rename_info;
	OFC_TCHAR *to_name;
	OFC_CHAR *sztoname;
	int status;
	OFC_CHAR *p;

	if (lpFileInformation != OFC_NULL) {
	  rename_info = lpFileInformation;

	  /* get the to name */
	  to_name = ofc_malloc(rename_info->FileNameLength +
			       sizeof(OFC_TCHAR));
	  ofc_tstrncpy(to_name, rename_info->FileName,
		       (rename_info->FileNameLength /
			sizeof(OFC_TCHAR)));
	  to_name[rename_info->FileNameLength / sizeof(OFC_TCHAR)] =
	    TCHAR_EOS;

	  sztoname = ofc_tstr2cstr(to_name);
	  /* convert \\ to / */
	  for (p = sztoname; *p != '\0'; p++)
	    if (*p == '\\')
	      *p = '/';

	  if (rename_info->ReplaceIfExists) {
	    /*
	     * Try to remove the target (don't care what it is)
	     * and don't care if it fails
	     */
	    rmdir(sztoname);
	    unlink(sztoname);
	  }

	  status = rename(context->name, sztoname);
	  ofc_free(context->name);
	  context->name = sztoname;

	  ofc_free(to_name);

	  if (status == 0)
	    ret = OFC_TRUE;
	  else
	    ofc_thread_set_variable
	      (OfcLastError,
	       (OFC_DWORD_PTR) TranslateError(errno));
	}
      }
      break;

    case OfcFileEndOfFileInfo: {
      OFC_FILE_END_OF_FILE_INFO *fileEof;
      off_t offset;
      int status;

      if (lpFileInformation != OFC_NULL) {
	fileEof = lpFileInformation;
	offset = (off_t) fileEof->EndOfFile;
	offset = lseek(context->fd, offset, SEEK_SET);
	if (offset >= 0) {
	  status = ftruncate(context->fd, offset);
	  if (status == 0)
	    ret = OFC_TRUE;
	  else
	    ofc_thread_set_variable(OfcLastError,
				    (OFC_DWORD_PTR)
				    TranslateError(errno));
	} else
	  ofc_thread_set_variable(OfcLastError,
				  (OFC_DWORD_PTR) TranslateError(errno));
      }
    }
      break;

    case OfcFileDispositionInfo: {
      OFC_FILE_DISPOSITION_INFO *fileDisposition;

      if (lpFileInformation != OFC_NULL) {
	fileDisposition = lpFileInformation;

	context->deleteOnClose = fileDisposition->DeleteFile;
	ret = OFC_TRUE;
      }
    }
      break;
    }
  }

  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);

  return ((OFC_BOOL) ret);
}

static OFC_DWORD OfcFSLinuxSetFilePointer(OFC_HANDLE hFile,
					  OFC_LONG lDistanceToMove,
					  OFC_PLONG lpDistanceToMoveHigh,
					  OFC_DWORD dwMoveMethod)
{
  OFC_DWORD ret;
  OFC_FS_LINUX_CONTEXT *context;
  off_t offset;
  int whence;

  ret = OFC_INVALID_SET_FILE_POINTER;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL || context->backup)
    {
      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(EPERM));
    }
  else
    {
      switch (dwMoveMethod)
	{
	default:
	case OFC_FILE_BEGIN:
	  whence = SEEK_SET;
	  break;
	case OFC_FILE_END:
	  whence = SEEK_END;
	  break;
	case OFC_FILE_CURRENT:
	  whence = SEEK_CUR;
	  break;
	}

      offset = lDistanceToMove;
#if defined(__USE_FILE_OFFSET64)
      if (sizeof(off_t) > sizeof(OFC_LONG) &&
	  lpDistanceToMoveHigh != OFC_NULL)
	offset |= (off_t) *lpDistanceToMoveHigh << 32;
#endif
      offset = lseek(context->fd, offset, whence);
      if (offset >= 0)
	{
	  ret = (OFC_DWORD) (offset & 0xFFFFFFFF);
#if defined(__USE_FILE_OFFSET64)
	  if (sizeof (off_t) > sizeof (OFC_LONG) && 
	      lpDistanceToMoveHigh != OFC_NULL)
	    *lpDistanceToMoveHigh = (offset >> 32 & 0xFFFFFFFF) ;
#endif
	}
      else
	ofc_thread_set_variable(OfcLastError,
				(OFC_DWORD_PTR) TranslateError(errno));

    }

    if (context != OFC_NULL)
      ofc_handle_unlock(hFile);

    return (ret);
}

static OFC_BOOL
OfcFSLinuxTransactNamedPipe(OFC_HANDLE hFile,
                             OFC_LPVOID lpInBuffer,
                             OFC_DWORD nInBufferSize,
                             OFC_LPVOID lpOutBuffer,
                             OFC_DWORD nOutBufferSize,
                             OFC_LPDWORD lpBytesRead,
                             OFC_HANDLE hOverlapped)
{
  return (OFC_FALSE);
}

static OFC_BOOL
OfcFSLinuxGetDiskFreeSpace(OFC_LPCTSTR lpRootPathName,
                            OFC_LPDWORD lpSectorsPerCluster,
                            OFC_LPDWORD lpBytesPerSector,
                            OFC_LPDWORD lpNumberOfFreeClusters,
                            OFC_LPDWORD lpTotalNumberOfClusters)
{
  OFC_BOOL ret;
  struct statfs fsstat;
  int status;
  OFC_CHAR *asciiPath;

  asciiPath = FilePath2LinuxPath(lpRootPathName);
  status = statfs(asciiPath, &fsstat);
  ofc_free(asciiPath);

  ret = OFC_FALSE;
  if (status >= 0) {
    ret = OFC_TRUE;
    *lpSectorsPerCluster = 1;
    *lpBytesPerSector = fsstat.f_bsize;
    *lpNumberOfFreeClusters = fsstat.f_bavail ;
    *lpTotalNumberOfClusters = fsstat.f_blocks ;
  } else
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(errno));

  return (ret);
}

static OFC_BOOL
OfcFSLinuxGetVolumeInformation(OFC_LPCTSTR lpRootPathName,
			       OFC_LPTSTR lpVolumeNameBuffer,
			       OFC_DWORD nVolumeNameSize,
			       OFC_LPDWORD lpVolumeSerialNumber,
			       OFC_LPDWORD lpMaximumComponentLength,
			       OFC_LPDWORD lpFileSystemFlags,
			       OFC_LPTSTR lpFileSystemName,
			       OFC_DWORD nFileSystemName)
{
  OFC_BOOL ret;

  ret = OFC_TRUE ;
  if (lpFileSystemName != OFC_NULL)
    ofc_tstrncpy (lpFileSystemName, TSTR("none"), nFileSystemName) ;

  if (lpVolumeNameBuffer != OFC_NULL)
    ofc_tstrncpy (lpVolumeNameBuffer, TSTR("none"), nVolumeNameSize) ;

  if (lpVolumeSerialNumber != OFC_NULL)
    *lpVolumeSerialNumber = '\0' ;

  if (lpMaximumComponentLength != OFC_NULL)
    *lpMaximumComponentLength = OFC_MAX_PATH ;

  if (lpFileSystemFlags != OFC_NULL)
    *lpFileSystemFlags = (OFC_DWORD) 0 ;

  return (ret) ;
}

/**
 * Unlock a region in a file
 * 
 * \param hFile
 * File Handle to unlock 
 *
 * \param length_low
 * the low order 32 bits of the length of the region
 *
 * \param length_high
 * the high order 32 bits of the length of the region
 *
 * \param hOverlapped
 * The overlapped structure which specifies the offset
 *
 * \returns
 * OFC_TRUE if successful, OFC_FALSE otherwise
 */
static OFC_BOOL OfcFSLinuxUnlockFileEx(OFC_HANDLE hFile,
				       OFC_UINT32 length_low,
				       OFC_UINT32 length_high,
				       OFC_HANDLE hOverlapped)
{
  OFC_BOOL ret;
  OFC_FS_LINUX_CONTEXT *context;
  int status;

  ret = OFC_FALSE;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL || context->backup) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    status = flock(context->fd, LOCK_UN);
    if (status == 0)
      ret = OFC_TRUE;
    else
      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(errno));
  }

  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);
  return (ret);
}

/**
 * Lock a region of a file
 * 
 * \param hFile
 * Handle to file to unlock region in 
 *
 * \param flags
 * Flags for lock
 *
 * \param length_low
 * Low order 32 bits of length of region
 *
 * \param length_high
 * High order 32 bits of length of region
 *
 * \param lpOverlapped
 * Pointer to overlapped structure containing offset of region
 *
 * \returns
 * OFC_TRUE if successful, OFC_FALSE otherwise
 */
static OFC_BOOL OfcFSLinuxLockFileEx(OFC_HANDLE hFile, OFC_DWORD flags,
				     OFC_DWORD length_low,
				     OFC_DWORD length_high,
				     OFC_HANDLE lpOverlapped)
{
  OFC_BOOL ret;
  OFC_FS_LINUX_CONTEXT *context;
  int status;
  int operation;

  ret = OFC_FALSE;
  context = ofc_handle_lock(hFile);

  if (context != OFC_NULL || context->backup) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    if (flags & OFC_LOCKFILE_EXCLUSIVE_LOCK)
      operation = LOCK_EX;
    else
      operation = LOCK_SH;
    if (flags & OFC_LOCKFILE_FAIL_IMMEDIATELY)
      operation |= LOCK_NB;

    status = flock(context->fd, operation);
    if (status == 0)
      ret = OFC_TRUE;
    else
      ofc_thread_set_variable(OfcLastError,
			      (OFC_DWORD_PTR) TranslateError(errno));
  }

  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);

  return (ret);
}

static OFC_BOOL OfcFSLinuxDismount(OFC_LPCTSTR filename) {
    OFC_BOOL ret;

    ret = OFC_TRUE;
    return (ret);
}

static OFC_FILE_FSINFO OfcFSLinuxInfo =
  {
   &OfcFSLinuxCreateFile,
   &OfcFSLinuxDeleteFile,
   &OfcFSLinuxFindFirstFile,
   &OfcFSLinuxFindNextFile,
   &OfcFSLinuxFindClose,
   &OfcFSLinuxFlushFileBuffers,
   &OfcFSLinuxGetFileAttributesEx,
   &OfcFSLinuxGetFileInformationByHandleEx,
   &OfcFSLinuxMoveFile,
   &OfcFSLinuxGetOverlappedResult,
   &OfcFSLinuxCreateOverlapped,
   &OfcFSLinuxDestroyOverlapped,
   &OfcFSLinuxSetOverlappedOffset,
   &OfcFSLinuxSetEndOfFile,
   &OfcFSLinuxSetFileAttributes,
   &OfcFSLinuxSetFileInformationByHandle,
   &OfcFSLinuxSetFilePointer,
   &OfcFSLinuxWriteFile,
   &OfcFSLinuxReadFile,
   &OfcFSLinuxCloseHandle,
   &OfcFSLinuxTransactNamedPipe,
   &OfcFSLinuxGetDiskFreeSpace,
   &OfcFSLinuxGetVolumeInformation,
   &OfcFSLinuxCreateDirectory,
   &OfcFSLinuxRemoveDirectory,
   &OfcFSLinuxUnlockFileEx,
   &OfcFSLinuxLockFileEx,
   &OfcFSLinuxDismount,
   OFC_NULL
  };

static OFC_DWORD
OfcFSLinuxAIOThread(OFC_HANDLE hThread, OFC_VOID *context)
{
  OFC_FSLINUX_OVERLAPPED *Overlapped;

  Overlapped = context;

  while (!ofc_thread_is_deleting(hThread)) {
    ofc_event_wait(Overlapped->hBusy);
    Overlapped->Errno = 0;
    if (Overlapped->opcode == OFC_FSLINUX_READ) {
      Overlapped->dwResult =
	(OFC_INT) pread(Overlapped->fd,
			(void *) Overlapped->lpBuffer,
			Overlapped->nNumberOfBytes,
			Overlapped->offset);

    } else if (Overlapped->opcode == OFC_FSLINUX_WRITE) {
      Overlapped->dwResult =
	(OFC_INT) pwrite(Overlapped->fd,
			 (void *) Overlapped->lpBuffer,
			 Overlapped->nNumberOfBytes,
			 Overlapped->offset);
    }
    if (Overlapped->opcode != OFC_FSLINUX_NOOP) {
      if (Overlapped->dwResult < 0)
	Overlapped->Errno = errno;
      ofc_event_set(Overlapped->hEvent);
    }
  }
  return (0);
}

OFC_VOID OfcFSLinuxStartup(OFC_VOID)
{
  ofc_fs_register(OFC_FST_LINUX, &OfcFSLinuxInfo);

  OfcFSLinuxAIOFreeQ = ofc_queue_create();
#if defined(OFC_PERF_STATS)
  prt_read = perf_rt_create(g_measurement, TSTR("Linux Read"), 0);
  prt_write = perf_rt_create(g_measurement, TSTR("Linux Write"), 0);
  pqueue_read = perf_queue_create(g_measurement, TSTR("Linux Read"), 0);
  pqueue_write = perf_queue_create(g_measurement, TSTR("Linux Write"), 0);
#endif
  g_instance = 0;
}

OFC_VOID OfcFSLinuxShutdown(OFC_VOID)
{
  OFC_HANDLE hOverlapped;
  OFC_FSLINUX_OVERLAPPED *Overlapped;

  for (hOverlapped = (OFC_HANDLE) ofc_dequeue(OfcFSLinuxAIOFreeQ);
       hOverlapped != OFC_HANDLE_NULL;
       hOverlapped = (OFC_HANDLE) ofc_dequeue(OfcFSLinuxAIOFreeQ)) {
    Overlapped = ofc_handle_lock(hOverlapped);
    if (Overlapped != OFC_NULL) {
      ofc_thread_delete(Overlapped->hThread);
      Overlapped->opcode = OFC_FSLINUX_NOOP;
      ofc_event_set(Overlapped->hBusy);
      ofc_thread_wait(Overlapped->hThread);

      ofc_event_destroy(Overlapped->hEvent);
      ofc_event_destroy(Overlapped->hBusy);
      ofc_free(Overlapped);
      ofc_handle_destroy(hOverlapped);
      ofc_handle_unlock(hOverlapped);
    }
  }
  ofc_queue_destroy(OfcFSLinuxAIOFreeQ);
  OfcFSLinuxAIOFreeQ = OFC_HANDLE_NULL;
#if defined(OFC_PERF_STATS)
  perf_rt_destroy(g_measurement, prt_read);
  perf_rt_destroy(g_measurement, prt_write);
  perf_queue_destroy(g_measurement, pqueue_read);
  perf_queue_destroy(g_measurement, pqueue_write);
#endif
}

int OfcFSLinuxGetFD(OFC_HANDLE hFile)
{
  int fd;
  OFC_FS_LINUX_CONTEXT *context;

  fd = -1;
  context = ofc_handle_lock(hFile);

  if (context == OFC_NULL || context->backup) {
    ofc_thread_set_variable(OfcLastError,
			    (OFC_DWORD_PTR) TranslateError(EPERM));
  } else {
    fd = context->fd;
  }

  if (context != OFC_NULL)
    ofc_handle_unlock(hFile);

  return (fd);
}

/** \} */
