/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <dev/usb/usb.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "sysdeps.h"

#define   TRACE_TAG  TRACE_USB
#include "adb.h"

#ifdef TRACE_USB
#define DBGW(x...) warn(x)
#else
#define DBGW(x...)
#endif

#define DBG	D

/* NOTE:
 *   I've no device to test this code, so how much correct it works
 *   is mystery. However, there is guarantee that event handling,
 *   interface and endpoints enumeration is implemented correctly.
 *   This was tested on USB devices, I've. Transmisison of data seems
 *   working, but there is no guarantee that related code contains no
 *   error. code logics was based on usb_osx.c && usb_linux.c with
 *   some peeping to libusb.
  */
static adb_mutex_t usb_lock = ADB_MUTEX_INITIALIZER;

struct usb_handle
{
        usb_handle *prev;
        usb_handle *next;

        /* path to device, e.g. /dev/ugen0 */
        char devname[32];
        /* in(0) and out(1) endpoints descriptors */
        int ep[2];
        /* in and out endpoints addresses */
        int ep_addr[2];
            
        /* device descriptor */
        int fd;
    
        int zero_mask;

        adb_cond_t notify;
        adb_mutex_t lock;

        /* ID of thread currently in REAPURB */
        pthread_t reaper_thread;
};

static usb_handle handle_list = {
        .prev = &handle_list,
        .next = &handle_list,
};

void
usb_cleanup()
{
}

static int
check_endpoint(usb_handle *uh, int ep, int mode)
{
        int     ep_addr = UE_GET_ADDR(ep);
        int     index  = (ep & UE_DIR_IN) ? 0 : 1;
        char   epbuf[32] = {0};
                
        if (uh->ep[index] < 0) {
                snprintf(epbuf, 32, "%s.%d", uh->devname, ep_addr);
    
                /* XXX: try rw mode, fall back to 'mode' if failed.
                 * This allows to open in/out endpoints with
                 * same ep_addr address (as it is done in libusb)
                 */
                int fd = adb_open(epbuf, O_RDWR);
    
                if ((fd < 0) && (errno == ENXIO))
                        fd = adb_open(epbuf, mode);
    
                if (fd < 0)
                    warn("can't open endpoint %s for bulk operations", epbuf);
    
                uh->ep[index] = fd;
        }
    
        return (uh->ep[index]);
}

static int
usb_bulk_write(usb_handle *uh, const void *data, int len)
{
        int fd, ret;

        int ep_addr = (uh->ep_addr[1]) & (~UE_DIR_IN);

        fd = check_endpoint(uh, ep_addr, O_WRONLY);
  
        if (fd < 0) {
                warn("failed to open endpoint %d for writing",
                    UE_GET_ADDR(ep_addr));
                return (-1);
        }
    
        int timeout = 100; /* 100 ms */
    
        ret = ioctl(fd, USB_SET_TIMEOUT, &timeout);
  
        if (ret < 0) {
                DBGW("failed to set timeout: %s");
                /* ignore error and try write anyway */
        }

        ret = adb_write(fd, data, len);

        if (ret < 0)
                warn("failed to write to bulk endpoint %s.%d",
                    uh->devname, UE_GET_ADDR(ep_addr));

        return (ret);
}

static int
usb_bulk_read(usb_handle *uh, void *data, int len)
{
        int fd, ret, one = 1;

        int ep_addr = uh->ep_addr[0] | UE_DIR_IN;

        fd = check_endpoint(uh, ep_addr, O_RDONLY);
  
        if (fd < 0) {
                warn("failed to open endpoint %d for reading",
                    UE_GET_ADDR(ep_addr));
                return (-1);
        }

        int timeout = 100; /* 100 ms */
    
        ret = ioctl(fd, USB_SET_TIMEOUT, &timeout);
  
        if (ret < 0) {
                DBGW("failed to set timeout");
                /* continue */
        }

        ret = ioctl(fd, USB_SET_SHORT_XFER, &one);
  
        if (ret < 0) {
                DBGW("failed to set short transfer");
                /* continue */
        }

        ret = adb_read(fd, data, len);
  
        if (ret < 0) {
                warn("failed to read from bulk endpoint %s.%d",
                    uh->devname, UE_GET_ADDR(ep_addr));
        }

        return (ret);
}


int
usb_write(usb_handle *uh, const void *_data, int len)
{
        unsigned char *data = (unsigned char *) _data;
        int n;
        int need_zero = 0;

        if (uh == NULL)
                return (-1);
    
        if (uh->zero_mask) {
                /* if we need 0-markers and our transfer
                 ** is an even multiple of the packet size,
                 ** we make note of it
                 */
                if (!(len & uh->zero_mask)) {
                        need_zero = 1;
                }
        }

        while (len > 0) {
                int xfer = (len > 4096) ? 4096 : len;

                n = usb_bulk_write(uh, data, xfer);
        
                if (n != xfer) {
                        warn("ERROR: n = %d\n", n);
            
                        return (-1);
                }

                len -= xfer;
                data += xfer;
        }

        if (need_zero) {
                return (usb_bulk_write(uh, _data, 0));
        }

        return (0);
}

int
usb_read(usb_handle *uh, void *_data, int len)
{
        unsigned char *data = (unsigned char *) _data;
        int n;

        if (uh == NULL)
                return (-1);
    
        DBG("++ usb_read ++\n");
    
        while (len > 0) {
                int xfer = (len > 4096) ? 4096 : len;

                DBG("[ usb read %d fd = %d], fname=%s\n", xfer, uh->fd, uh->devname);
        
                n = usb_bulk_read(uh, data, xfer);
                DBG("[ usb read %d ] = %d, fname=%s\n", xfer, n, uh->devname);
        
                if (n != xfer) {
                        if ((errno == ETIMEDOUT) && (uh->fd != -1)) {
                                DBG("[ timeout ]\n");
                
                                if (n > 0){
                                        data += n;
                                        len -= n;
                                }
                
                                continue;
                        }
           
                        DBGW("ERROR: n = %d", n);
            
                        return (-1);
                }

                len -= xfer;
                data += xfer;
        }

        DBG("-- usb_read --\n");
    
        return (0);
 }

int
usb_close(usb_handle *h)
{
        DBG("[ usb close ... ]\n");
    
        adb_mutex_lock(&usb_lock);
    
        h->next->prev = h->prev;
        h->prev->next = h->next;
        h->prev = 0;
        h->next = 0;

        adb_close(h->fd);
    
        DBG("[ usb closed %p (fd = %d) ]\n", h, h->fd);
    
        adb_mutex_unlock(&usb_lock);

        free(h);
        
        return (0);
}

int
poll_usb_events(int fd)
{
        struct pollfd ps;

        ps.fd = fd;
        ps.events = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
        ps.revents = POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
	
        return (poll(&ps, 1, -1));
}

int
check_usb_interface(int f, struct usb_device_info *info,
    int cindex, int iindex, int aindex, usb_handle *uh)
{
        struct usb_interface_desc idesc;
        struct usb_endpoint_desc edesc;
        int e;
    
        idesc.uid_config_index = cindex;
        idesc.uid_interface_index = iindex;
        idesc.uid_alt_index = aindex;
        
        bzero(uh, sizeof(struct usb_handle));
        
        uh->ep[0] = -1;
        uh->ep[1] = -1;
        
        if (ioctl(f, USB_GET_INTERFACE_DESC, &idesc) <0) {
                warn("ioctl USB_GET_INTERFACE_DESC failed");
                return (-1);
        }

        if (idesc.uid_desc.bNumEndpoints != 2)  {
                DBG("Interface has not 2 endpoints, ignoring\n");
                return (0);
        }
    
        edesc.ued_config_index = cindex;
        edesc.ued_interface_index = iindex;
        edesc.ued_alt_index = aindex;
	
        for (e = 0; e < idesc.uid_desc.bNumEndpoints; e++) {
                edesc.ued_endpoint_index = e;
                
                if (ioctl(f, USB_GET_ENDPOINT_DESC, &edesc) < 0) {
                        warn("ioctl USB_GET_ENDPOINT_DESC failed");
                        return (-1);
                }
            
                if (edesc.ued_desc.bmAttributes != UE_BULK) {
                        DBG("endpoint is not bulk, ignoring\n");
                        return (0);
                }

                if (edesc.ued_desc.bEndpointAddress & UE_DIR_IN)
                        uh->ep_addr[0] = edesc.ued_desc.bEndpointAddress;
                else
                        uh->ep_addr[1] = edesc.ued_desc.bEndpointAddress;
        }

        if (!is_adb_interface(info->udi_vendorNo, 
			      info->udi_productNo,
                              idesc.uid_desc.bInterfaceClass,
                              idesc.uid_desc.bInterfaceSubClass,
                              idesc.uid_desc.bInterfaceProtocol))
        {
                return (0);
        }
                            
        /* aproto 01 needs 0 termination */
        if (idesc.uid_desc.bInterfaceProtocol == 0x01) {
                uh->zero_mask = UGETW(edesc.ued_desc.wMaxPacketSize) - 1;
        }
  
        return (1);
}

int
register_device(struct usb_handle *uh, int interface,  const char *serial)
{
        struct usb_handle  *usb = NULL;
   
        adb_mutex_lock(&usb_lock);
    
        /* XXX: this is only sanity check
         *   as we are using USB events polling, same device name must not be
         *   in list of known devices.
         */  
        for (usb = handle_list.next; usb != &handle_list; usb = usb->next) {
                if (strcmp(usb->devname, uh->devname) == 0) {
                        adb_mutex_unlock(&usb_lock);
                        return (0);
                }
        }

        adb_mutex_unlock(&usb_lock);

        DBG("[ usb located new device %s (%d/%d/%d) ]\n",
            uh->devname, uh->ep_addr[0], uh->ep_addr[1], interface);
    
        usb = calloc(1, sizeof(struct usb_handle));
        bcopy(uh, usb, sizeof(struct usb_handle));
    
        adb_cond_init(&usb->notify, 0);
        adb_mutex_init(&usb->lock, 0);
    
        usb->reaper_thread = 0;

        if (usb->fd < 0)
                goto fail;
    
        DBG("[ usb open %s fd = %d]\n", usb->devname, usb->fd);

        /* add to the end of the active handles */
        adb_mutex_lock(&usb_lock);
        usb->next = &handle_list;
        usb->prev = handle_list.prev;
        usb->prev->next = usb;
        usb->next->prev = usb;
    
        adb_mutex_unlock(&usb_lock);

        register_usb_transport(usb, serial);
    
        return (1);

fail:
        DBGW("[ usb open %s]", usb->devname);
        
        free(usb);
        
        return (-1);
}

void
check_usb_device_attach(struct usb_device_info *info)
{
        char                                    devname[32];
        int                                     found = 0;
        struct usb_handle                       uh;
        struct usb_config_desc cdesc;
        int                                     i = 0;
        char                                    serial[256];
    
        if (info->udi_devnames[0][0] == '\0') 
               return;
    
        snprintf(devname, 32,  "/dev/%s", info->udi_devnames[0]);
	
        DBG("probing usb device %s [V: %04x P: %04x (%s %s rel. %s]\n",
            devname,
            info->udi_vendorNo, info->udi_productNo,
            info->udi_vendor, info->udi_product, info->udi_release);
    
        int fd = adb_open(devname, O_RDONLY);
    
        if (fd < 0) {
                warn("failed to open device %s for reading", devname);
                return;
        }

        cdesc.ucd_config_index = USB_CURRENT_CONFIG_INDEX;

        if (ioctl(fd, USB_GET_CONFIG_DESC, &cdesc) < 0) {
                warn("failed to get configuration for device %s", devname);
                return;
        }
	
        for ( ; i < cdesc.ucd_desc.bNumInterface; ++i) {
                if (check_usb_interface(fd, info, cdesc.ucd_config_index, i,
                    USB_CURRENT_ALT_INDEX, &uh) > 0)
                 {
                        // found some interface and saved information about it
                        found = 1;
                        break;
                 }
        }
        
        if (found == 1) {
                // read the device's serial number
                bzero(serial, sizeof(serial));
             
                usb_device_descriptor_t ddesc;
                
                if (ioctl(fd, USB_GET_DEVICE_DESC, &ddesc) < 0) {
                        warn("failed to get descriptor for device %s", devname);
                        return;
                }
            
                if (ddesc.iSerialNumber) {
                        struct usb_ctl_request ctrl;
                        uint16_t               buffer[128];
                        int                    result;

                        bzero(buffer, sizeof(buffer));
                        bzero(&ctrl, sizeof(ctrl));

                        ctrl.ucr_request.bmRequestType = UT_READ_DEVICE;
                        ctrl.ucr_request.bRequest = UR_GET_DESCRIPTOR;
                        USETW2(ctrl.ucr_request.wValue, UDESC_STRING, ddesc.iSerialNumber);
                        USETW(ctrl.ucr_request.wIndex,  0);
                        USETW(ctrl.ucr_request.wLength, sizeof(buffer));
                        ctrl.ucr_flags = USBD_SHORT_XFER_OK;
                        ctrl.ucr_data = buffer;

                        result = ioctl(fd, USB_DO_REQUEST, &ctrl);
                    
                        if (result > 0) {
                                int i = 1;
                                /* skip first word, and copy the rest to the
                                 * serial string, changing shorts to bytes.
                                 */
                                result /= 2;
                            
                                for ( ; i < result; ++i)
                                        serial[i - 1] = buffer[i];
                            
                                serial[i - 1] = 0;
                        }
                }

                /* saving device name */
                bcopy(devname, uh.devname, 32);
                uh.fd = fd;
                
                if (register_device(&uh,  i, serial) > 0) {
                        return;
                }
        }

        adb_close(fd);
}

void usb_kick(usb_handle *h)
{
        DBG("[ kicking %p (fd = %d) ]\n", h, h->fd);
    
        adb_mutex_lock(&h->lock);
    
        if (h->reaper_thread) {
                pthread_kill(h->reaper_thread, SIGALRM);
        }

        /* closing endpoints */
        int i = 0;
    
        for ( ; i < 2; ++i) {
                if (h->ep[i] > 0) {
                        adb_close(h->ep[i]);
                        h->ep[i] = -1;
                }
        }
        
        adb_cond_broadcast(&h->notify);
        adb_mutex_unlock(&h->lock);
}

void
check_usb_device_detach(struct usb_device_info *info)
{
        usb_handle *usb;
        char devname[32] = {0};
    
        if (info->udi_devnames[0][0] == '\0') 
                return;
    
        snprintf(devname, 32,  "/dev/%s", info->udi_devnames[0]);
    
        adb_mutex_lock(&usb_lock);
        /* removing device from list */
    
        for(usb = handle_list.next; usb != &handle_list; usb = usb->next){
                if (strcmp(usb->devname, devname) == 0) {
                        usb_kick(usb);
                }
        }
    
        adb_mutex_unlock(&usb_lock);
}

void
dispatch_usb_events(int fd)
{
        struct usb_event ev;
        bzero(&ev, sizeof(ev));

        while (sizeof(ev) ==  adb_read(fd, &ev, sizeof(ev))) {
                switch (ev.ue_type) {
                case USB_EVENT_CTRLR_ATTACH:
                case USB_EVENT_CTRLR_DETACH:
                case USB_EVENT_DRIVER_ATTACH:
                case USB_EVENT_DRIVER_DETACH:
                        break;

                case USB_EVENT_DEVICE_ATTACH:
                        check_usb_device_attach(&ev.u.ue_device);
                        break;

                case USB_EVENT_DEVICE_DETACH:
                        check_usb_device_detach(&ev.u.ue_device);
                        break;

                default:
                        break;
                }
        }
}

void *
device_poll_thread(void* unused)
{
        DBG("Created device thread\n");
    
        int fd = adb_open("/dev/usb", O_RDONLY);

        if (fd == -1) {
                DBGW("failed to open /dev/usb to fetch events");
                return (NULL);
        }
    
        for (;;) {
                if (poll_usb_events(fd) > 0) {
                        dispatch_usb_events(fd);
                } else {
                        err(EX_IOERR, "failed to poll usb event");
			/* never returning from err */
                }
        }
    
    	/* never reaching this point */
        return (NULL);
}

static void
sigalrm_handler(int signo)
{
    // don't need to do anything here
}

void
usb_init()
{
        adb_thread_t        tid;
        struct sigaction actions;

        memset(&actions, 0, sizeof(actions));
    
        sigemptyset(&actions.sa_mask);
    
        actions.sa_flags = 0;
        actions.sa_handler = sigalrm_handler;
    
        sigaction(SIGALRM,& actions, NULL);

        if (adb_thread_create(&tid, device_poll_thread, NULL)) {
                err(EX_OSERR, "cannot create input thread");
        }
}
