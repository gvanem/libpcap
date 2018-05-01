/*
 * Copyright (c) 2011, Dustin Johnson (Dustin@Dustinj.us)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __PCAP_PLUGIN_INTERFACE_H__
#define __PCAP_PLUGIN_INTERFACE_H__

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <windows.h>

/* If set in a plugin implementation file, we export the below functions from
 * those files. We cannot export ANY data.
 */
#if defined(COMPILING_PCAP_PLUGIN)
  #define PLUGIN_API __declspec(dllexport)
#else
  #define PLUGIN_API __declspec(dllimport)

  #undef  TRACE_COLOR_START
  #define TRACE_COLOR_START TRACE_COLOR_MAGENTA

  #undef  TRACE_COLOR_ARGS
  #define TRACE_COLOR_ARGS  TRACE_COLOR_YELLOW
#endif

#ifndef UNUSED
#define UNUSED(x) (void)x
#endif

/** \brief A plugin defined type that defaults to \p void.
 * Plugins can override this type by defining it before the inclusion of this header file.
 */
#ifndef PLUGIN_INSTANCE_TYPE
#define PLUGIN_INSTANCE_TYPE void
#endif

/** \brief The API version identifier that is to be used with #GetPluginApiVersion
 */
#define PLUGIN_API_VERSION 1

/** \brief
  *   Used in conjunction with #GetDeviceList and #FreeDeviceList to list
  *   the available devices.
  *
  * \param name
  *   The machine identifier for the device. This parameter will be passed to
  *   #OpenInstance to specify which device to open.
  *
  * \param description
  *   The user-friendly description description string for the device.
  *
  * \param next
  *   A pointer to the next device description in the linked list. If no such
  *   device exists or the end of the list has been reached then this parameter
  *   must be NULL.
  *
  * \remark This structure is allocated and released by the plugin.
  *
  * \see GetDeviceList FreeDeviceList OpenInstance
  *
  */
typedef struct _PLUGIN_DEVICE_DESCRIPTION {
        char                               name[512];
        char                               description[512];
        struct _PLUGIN_DEVICE_DESCRIPTION *next;
      } PLUGIN_DEVICE_DESCRIPTION;

/** \brief
  * Used in conjunction with #GetStats to retrieve device capture statistics.
  *
  * \param received
  *   The number of packets received by the interface since it was opened.
  *
  * \param dropped
  *   The number of packets dropped by the interface since it was opened.
  *
  * \see GetStats
  */
typedef struct _PLUGIN_STATS {
        UINT received;
        UINT dropped;
      } PLUGIN_STATS;

/** \brief
  *   Used in conjunction with #GetNextPacket to carry the particulars of
  *   the delivered packet.
  *
  * \param tv_sec
  *   The number of seconds that has elapsed since January 1st 1970.
  *
  * \param tv_usec
  *   The number of microseconds that has elapsed since the last full second.
  *
  * \param caplen
  *   The number of the packet's bytes that are present in the packet buffer
  *   and are available to be read.
  *
  * \param len
  *   The number of bytes originally available when the packet was read
  *   into the device.
  *
  * \see GetNextPacket
  */
typedef struct _PLUGIN_PACKET_HEADER {
        struct _PLUGIN_TIMEVAL  {
               UINT32 tv_sec;   /* Seconds */
               UINT32 tv_usec;  /* Microseconds */
             } ts;
        UINT32 caplen;          /* Length of portion present */
        UINT32 len;             /* Length this packet (off wire) */
      } PLUGIN_PACKET_HEADER;

/** \brief
  *   Used in conjunction with #SetDirection to specify the direction
  *   of traffic to capture.
  *
  * \see SetDirection
  */
typedef enum _PLUGIN_DIRECTION {
        PLUGIN_DIRECTION_INOUT = 0,
        PLUGIN_DIRECTION_IN,
        PLUGIN_DIRECTION_OUT
      } PLUGIN_DIRECTION;

/** \brief
  *   Used in conjunction with #SetMode to specify the capture mode that
  *   is to be used.
  *
  * \see SetMode
  */
typedef enum _PLUGIN_MODE {
        PLUGIN_MODE_CAPT = 0,
        PLUGIN_MODE_STAT
      } PLUGIN_MODE;

/** \brief
 *    Convenience macro to allow the plugin infrastructure to use the same
 *    interface definition as the plugins. Also add the function prototype with
 *    a '__declspec(dllexport)' here to avoid using a .def-file for every plugin.
 */
#define PLUGIN_FUNCTION(type, name, args) \
        typedef type (__cdecl * t_ ##name) args; \
        type /* __declspec(dllexport) */ PLUGIN_API name args

/** \name Required
  * @{
  */
/**
 * \brief Returns the plugin API version with which the plugin was compiled.
 *
 * \return This function is to always return #PLUGIN_API_VERSION.
 *
 * \remark This function serves to allow a simple version scheme that gives the
 *         plugin framework some ability to change over time.
 * \remark The plugin framework will determine if it is compatible with
 *         the API version returned.
 *         If the plugin is not compatible it will not be loaded.
 */
PLUGIN_FUNCTION (size_t, GetPluginApiVersion, (void));

/**
 * \brief Returns the user-friendly name of the plugin.
 *
 * \param[out] name Pointer to a buffer in which to place the plugin's user-friendly name.
 * \param[in] nameSizeInBytes The size in bytes of the buffer referenced by \p name.
 *
 * \return TRUE if the request succeeds, FALSE otherwise.
 *
 * \remark If this function fails it is to return FALSE. In the event of such a failure,
 *         the name parameter may be set to anything as it will be discarded.
 * \remark If TRUE is returned then the name parameter must point to a null terminated
 *         ASCII string that is no longer than the supplied nameSizeInBytes parameter.
 */
PLUGIN_FUNCTION (BOOL, GetPluginName, (OUT char* name, size_t nameSizeInBytes));

/**
 * \brief Returns the devices to which the plugin has access.
 *
 * \param[out] devices Pointer to a linked list of device descriptions.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes.
 *             If an error occurs, this buffer must contain a null-terminated and user-friendly
 *             error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the request succeeds, FALSE otherwise.
 *
 * \remark If this function fails it is to return FALSE and set \p errorMsg accordingly.
 *         In the event of such a failure, the devices parameter may be set to anything
 *         as it will be discarded.
 * \remark If TRUE is returned then the devices parameter must point to a linked list of
 *         device descriptions. If TRUE is returned, the errorMsg parameter is ignored.
 *
 * \see FreeDeviceList OpenInstance
 */
PLUGIN_FUNCTION (BOOL, GetDeviceList,
                 (OUT PLUGIN_DEVICE_DESCRIPTION **devices,
                  OUT  char                      *errorMsg,
                  size_t                          errorMsgSizeInBytes));

/**
 * \brief Releases a device list retrieved from #GetDeviceList.
 *
 * \param[in,out] devices The device list to be released.
 *
 * \remark This function cannot fail.  After calling this function,
 *         memory pointed to by \p devices is no longer accessible.
 *
 * \see GetDeviceList
 */
PLUGIN_FUNCTION (void, FreeDeviceList, (IN OUT PLUGIN_DEVICE_DESCRIPTION *devices));

/**
 * \brief Creates an instance of the specified device for use with many other functions.
 *
 * \param[in] deviceName
 *            The name of the device to open as found in the device list retrieved
 *            from #GetDeviceList.
 *
 * \param[out] instanceHandle
 *             A pointer to a plugin-defined instance handle. The plugin will use this
 *             handle to store instance-specific information.
 *
 * \param[out] errorMsg
 *             Pointer to a character buffer of length \p errorMsgSizeInBytes.
 *             If an error occurs, this buffer must contain a null-terminated
 *             and user-friendly error description.
 *
 * \param[in] errorMsgSizeInBytes
 *            The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \remark
 *   If this function fails it is to return FALSE and set \p errorMsg accordingly.
 *   In the event of such a failure, the instanceHandle parameter may be set to
 *    anything as it will be discarded.
 *
 * \remark
 *   If TRUE is returned then \p instanceHandle must point to a valid plugin-specific
 *   instance handle. If TRUE is returned, the errorMsg parameter is ignored.
 *
 * \see GetDeviceList CloseInstance
 */
PLUGIN_FUNCTION (BOOL, OpenInstance,
                 (IN  char                  *deviceName,
                  OUT PLUGIN_INSTANCE_TYPE **instanceHandle,
                  OUT char                  *errorMsg,
                  IN  size_t errorMsgSizeInBytes));

/**
 * \brief Releases the device that was retrieved from #OpenInstance.
 *
 * \param[in] instanceHandle
 *   The plugin specific handle for the device as returned by #OpenInstance.
 *
 * \remark
 *   This function cannot fail. After invocation, \p instanceHandle
 *   is no longer valid and should be discarded.
 *
 * \remark
 *   This function must return the system to a state such that repeated
 *   calls to open and close a device produces no accumulating effects.
 *
 * \see OpenInstance
 */
PLUGIN_FUNCTION (void, CloseInstance,
                (IN PLUGIN_INSTANCE_TYPE *instanceHandle));

/**
 * \brief Returns the link type of packets retrieved with #GetNextPacket.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 *
 * \return The link type of packets retrieved with #GetNextPacket as defined in bpf.h.
 *
 * \remark This function cannot fail.
 *
 * \see GetSupportedDlts GetNextPacket
 */
PLUGIN_FUNCTION (int, GetLinkType, (IN PLUGIN_INSTANCE_TYPE *instanceHandle));

/** @} */

/** \name Optional
  * @{
  */
/**
 * \brief Returns a list of Data Link Types that the device supports.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as
 *            returned by #OpenInstance.
 *
 * \param[in,out] dltList A pointer to an array that will hold the DLT list.
 *                This array must be at least \p dltListSizeInBytes bytes long.
 *
 * \param[in] dltListSizeInBytes The size in bytes of the memory pointed to by \p dltList.
 *
 * \param[out] dltCount The number of DLTs that were stored in \p dltList.
 *
 * \return FALSE if \p dltListSizeInBytes is not large enough to populate all
 *               supported DLTs into \p dltList.  TRUE in all other cases.
 *
 * \remark This function may only be implemented if #SetDatalink is also implemented.
 * \remark This may by called multiple times with a larger \p dltListSizeInBytes
 *         each succeeding time until success is reported.
 *
 * \see SetDatalink
 */
PLUGIN_FUNCTION (BOOL, GetSupportedDlts,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN  OUT UINT             *dltList,
                  IN  size_t                dltListSizeInBytes,
                  OUT size_t               *dltCount));

/**
 * \brief Returns packet reception statistics.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as
 *            returned by #OpenInstance.
 *
 * \param[out] stats A pointer to a structure that is to be populated with device statistics.
 *
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes.
 *             If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 *
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if \p stats has been set to the current statistics for the device.
 *         FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a
 *         null-terminated and user-friendly error description.
 */
PLUGIN_FUNCTION (BOOL, GetStats,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  OUT PLUGIN_STATS         *stats,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Sets the Berkeley Packet Filter (BPF) that is to be used to filter packets.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 *
 * \param[in] filter Compiled BPF filter that is to be set in the device.
 *
 * \param[in] filterSizeInBytes The size in bytes of \p filter.
 *
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes.
 *                      If an error occurs, this buffer must contain a null-terminated and
 *                      user-friendly error description.
 *
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the BPF filter was successfully configured. FALSE in all other cases.
 *         If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly
 *         error description.
 */
PLUGIN_FUNCTION (BOOL, SetPacketFilter,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN  const void           *filter,
                  IN  size_t                filterSizeInBytes,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Sets the maximum time to wait for new packets to arrive.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 *
 * \param[in] timeoutMs The maximum number of milliseconds to wait for new packets to arrive
 *                      before fulfilling a read request.
 *
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes.
 *                      If an error occurs, this buffer must contain a null-terminated and
 *                      user-friendly error description.
 *
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the read timeout was successfully configured. FALSE in all other cases.
 *         If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly
 *         error description.
 */
PLUGIN_FUNCTION (BOOL, SetReadTimeout,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN  int                   timeoutMs,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Returns the location of the next packet received by the device and its header.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[out] packetHeader A pointer to the header of the next packet read from the device.
 * \param[out] packet A pointer to the packet data for the next packet read from the device.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the capture direction was successfully configured. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 *
 * \remark Packet and header data as returned by \p packetHeader and \p packet respectively need only remain valid from one call of #GetNextPacket to the next, allowing for the header and packet data memory to be reused by the plugin.
 */
PLUGIN_FUNCTION (BOOL, GetNextPacket,
                 (IN  PLUGIN_INSTANCE_TYPE  *instanceHandle,
                  OUT PLUGIN_PACKET_HEADER **packetHeader,
                  OUT void                 **packet,
                  OUT char                  *errorMsg,
                  IN  size_t                 errorMsgSizeInBytes));

/**
 * \brief Returns the event that gets signaled when the device has at least the minimum bytes to copy available for read.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[out] readEvent A handle to the read event for the device instance.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the read event was returned successfully. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 *
 * \see GetNextPacket SetMinToCopy
 */
PLUGIN_FUNCTION (BOOL, GetReadEvent,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  OUT HANDLE               *readEvent,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Injects a given packet into the device's network medium.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[in] packet A pointer to the packet data to be sent by the device.
 * \param[in] packetSizeInBytes The size in bytes of packet pointed to by \p packet.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the capture direction was successfully configured. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 *
 */
PLUGIN_FUNCTION (BOOL, InjectPacket,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN  const void           *packet,
                  IN  size_t                packetSizeInBytes,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Sets a filter indicating from which direction to capture network traffic.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[in] direction The direction from which to capture network traffic.  All other traffic is to be ignored.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the capture direction was successfully configured. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 */
PLUGIN_FUNCTION (BOOL, SetDirection,
                 (IN PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN PLUGIN_DIRECTION      direction,
                  OUT char                *errorMsg,
                  IN  size_t               errorMsgSizeInBytes));

/**
 * \brief Sets the data link to use for delivering network traffic.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[in] dlt The Data Link Type (DLT) that packets delivered via #GetNextPacket are to have.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the DLT was successfully configured. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 *
 * \see GetSupportedDlts
 */
PLUGIN_FUNCTION (BOOL, SetDatalink,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN  int                   dlt,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Retrieves the blocking state of the plugin.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[out] nonBlocking TRUE if the device is operating in non-blocking mode, FALSE otherwise.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the requested non-blocking mode was successfully configured. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 *
 * \see SetNonBlocking
 */
PLUGIN_FUNCTION (BOOL, IsNonBlocking,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  OUT BOOL                 *nonBlocking,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Sets the blocking state of the plugin.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[in] nonBlocking TRUE if the device is to operate in non-blocking mode, FALSE otherwise.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the requested non-blocking mode was successfully configured. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 *
 * \see IsNonBlocking
 */
PLUGIN_FUNCTION (BOOL, SetNonBlocking,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN  BOOL                  nonBlocking,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Sets the kernel mode buffer size of the plugin.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[in] sizeInBytes The size in bytes of the kernel mode buffer.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the kernel mode buffered was successfully configured with the requested size. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 *
 * \see SetMinToCopy
 */
PLUGIN_FUNCTION (BOOL, SetBufferSize,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN  size_t                sizeInBytes,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Sets the capture mode of the plugin.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[in] mode The capture mode in which the device is to operate.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the capture mode was successfully configured. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 */
PLUGIN_FUNCTION (BOOL, SetMode,
                 (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN  PLUGIN_MODE           mode,
                  OUT char                 *errorMsg,
                  IN  size_t                errorMsgSizeInBytes));

/**
 * \brief Sets the minimum amount of data that must be present in the device before it is made accessible.
 *
 * \param[in] instanceHandle The plugin specific handle for the device as returned by #OpenInstance.
 * \param[in] sizeInBytes The size in bytes that must be present in the device before it is made accessible for a read operation.
 * \param[out] errorMsg Pointer to a character buffer of length \p errorMsgSizeInBytes. If an error occurs, this buffer must contain a null-terminated and user-friendly error description.
 * \param[in] errorMsgSizeInBytes The size in bytes of the buffer referenced by \p errorMsg.
 *
 * \return TRUE if the minimum to copy was successfully configured with the requested size. FALSE in all other cases.  If FALSE is returned \p errorMsg must contain a null-terminated and user-friendly error description.
 *
 * \see SetBufferSize
 */
PLUGIN_FUNCTION (BOOL, SetMinToCopy,
                 (IN PLUGIN_INSTANCE_TYPE *instanceHandle,
                  IN size_t                sizeInBytes,
                  OUT char                *errorMsg,
                  IN  size_t               errorMsgSizeInBytes));
/** @} */

#endif /* __PCAP_PLUGIN_INTERFACE_H__ */
