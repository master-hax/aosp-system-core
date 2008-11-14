#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <dev/usb/usb.h>

#include "usb.h"

#ifdef TRACE_USB
#define DBGW(x...) warn(x)
#define DBG(x...)   fprintf(stderr, x)
#else
#define DBGW(x...)
#define DBG(x...)
#endif

/* NOTE: same as for adb related usb code
 *   I've no device to test this code, so how much correct it works
 *   is mystery. However, there is guarantee that devices,
 *   interfaces and endpoints enumeration is implemented correctly.
 *   This was tested on USB devices, I've. Transmisison of data seems
 *   working, but there is no guarantee that related code contains no
 *   error. code logics was based on usb_osx.c && usb_linux.c with
 *   some peeping to libusb and usbdevs.
 */
	
struct usb_handle 
{
        char   devname[32];
        int     fd;
        int     ep[2];
        /* in and out endpoints addresses */
        int     ep_addr[2];
            
};

int
filter_usb_device(int f, struct usb_device_info *info,
    int cindex, int iindex, int aindex, struct usb_handle *uh, 
    usb_ifc_info *ifc_info)
{
        struct usb_interface_desc  idesc;
        struct usb_endpoint_desc    edesc;
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
                return (-1);
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

        ifc_info->ifc_class = idesc.uid_desc.bInterfaceClass;
        ifc_info->ifc_subclass = idesc.uid_desc.bInterfaceSubClass;
        ifc_info->ifc_protocol = idesc.uid_desc.bInterfaceProtocol;
    
        return (1);
}

struct usb_handle *
check_usb_device(struct usb_device_info *info, ifc_match_func callback)
{
        char                                    devname[32];
        int                                      found = 0;
        struct usb_handle           uh;
        struct usb_config_desc cdesc;
        int                                      i = 0;
        struct usb_ifc_info       ifc_info;
      
        if (info->udi_devnames[0][0] == '\0') 
               return (NULL);
    
        snprintf(devname, 32,  "/dev/%s", info->udi_devnames[0]);
        DBG("probing usb device %s [V: %04x P: %04x (%s %s rel. %s]\n",
            devname,
            info->udi_vendorNo, info->udi_productNo,
            info->udi_vendor, info->udi_product, info->udi_release);
    
        int fd = open(devname, O_RDONLY);
    
        if (fd < 0) {
                DBGW("failed to open device %s for reading", devname);
                return (NULL);
        }

        cdesc.ucd_config_index = USB_CURRENT_CONFIG_INDEX;

        if (ioctl(fd, USB_GET_CONFIG_DESC, &cdesc) < 0) {
                warn("failed to get configuration for device %s", devname);
                return (NULL);
        }
	
        for ( ; i < cdesc.ucd_desc.bNumInterface; ++i) {
                if (filter_usb_device(fd, info, cdesc.ucd_config_index, i,
                    USB_CURRENT_ALT_INDEX, &uh, &ifc_info) > 0)
                 {
                        // found some interface and saved information about it
                        found = 1;
                        break;
                 }
        }
        
        if (found == 1) {
                // read the device's serial number
                bzero(ifc_info.serial_number, sizeof(ifc_info.serial_number));
            
                usb_device_descriptor_t ddesc;
                
                if (ioctl(fd, USB_GET_DEVICE_DESC, &ddesc) < 0) {
                        warn("failed to get device %s descriptor", devname);
                        return (NULL);
                }
            
                if (ddesc.iSerialNumber) {
                        struct usb_ctl_request ctrl;
                        uint16_t                            buffer[128];
                        int                                      result;

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
                                        ifc_info.serial_number[i - 1] = buffer[i];
                          }
                }
            
                ifc_info.has_bulk_in = (uh.ep_addr[0] != 0);
                ifc_info.has_bulk_out = (uh.ep_addr[1] != 0);
                ifc_info.dev_vendor = info->udi_vendorNo;
                ifc_info.dev_product = info->udi_productNo;
                ifc_info.dev_class = info->udi_class;
                ifc_info.dev_subclass = info->udi_subclass;
                ifc_info.dev_protocol = info->udi_protocol;
            
                 if (callback(&ifc_info) == 0) {
                        /* saving device name */
                        bcopy(devname, uh.devname, 32);
                        uh.fd = fd;
                     
                        struct usb_handle *ret =
                            (struct usb_handle *)calloc(1, sizeof(struct usb_handle));
                     
                        bcopy(&uh, ret, sizeof(struct usb_handle));
                     
                        return (ret);
                 }
        }

        return (NULL);
}
 /* 
  * based on usbdevs
  */
char done[USB_MAX_DEVICES];

struct usb_handle *
explore_device(int fd, int addr, ifc_match_func callback)
{
        struct usb_device_info info;
        struct usb_handle *uh = NULL;
        int res, i, port;

        info.udi_addr = addr;
    
        res = ioctl(fd, USB_DEVICEINFO, &info);
    
        if (res) {
                if (errno != ENXIO)
                        warn("failed to explore device addr %d", addr);

                return (NULL);
        }
 	
        done[addr] = 1;

        uh = check_usb_device(&info, callback);
    
        if (uh != NULL)
                return (uh);
                         
        for (port = 0; port < info.udi_nports; ++port) {
                int daddr = info.udi_ports[port];
    
                if (daddr >= USB_MAX_DEVICES) {
                        continue;
                }

                if (daddr == 0) {
                        DBG("addr 0 is invalid USB device address\n");
                        continue;
                }
                
                uh = explore_device(fd, daddr, NULL);
            
                if (uh != NULL)
                        break;
        }

        return (uh);
}

static struct usb_handle *
find_usb_device(ifc_match_func callback)
{
        int i;
        char buf[64];
        struct usb_handle *uh = NULL;
    
        memset(done, 0, sizeof(done));
    
        /* enumerating controllers */
        for (i = 0; i < 10; i++) {
                snprintf(buf, sizeof(buf), "/dev/usb%d", i);
                int f = open(buf, O_RDONLY);
                
                if (f >= 0) {
                        DBG("scanning controller %s\n", buf);
                    
                        /* enumerating devices */
                        int cont;

                        for (cont = 1; cont < USB_MAX_DEVICES; ++cont) {
                                if (done[cont] == 1)
                                        continue;
                                
                                uh = explore_device(f, cont, callback);
                        }
                    
                        close(f);
                    
                        if (uh != NULL)
                                break;
                }
        }
    
        return (uh);
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
                int fd = open(epbuf, O_RDWR);
    
                if ((fd < 0) && (errno == ENXIO))
                        fd = open(epbuf, mode);
    
                if (fd < 0)
                        warn("can't open endpoint %s for bulk operations",  epbuf);
    
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
                DBGW("failed to set timeout");
                /* ignore error and try write anyway */
        }

        ret = write(fd, data, len);

        if (ret < 0)
                warn("failed to write to bulk endpoint %s.%d",
                    uh->devname, UE_GET_ADDR(ep_addr));

        return (0);
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

        ret = read(fd, data, len);
  
        if (ret < 0) {
                warn("failed to read from bulk endpoint %s.%d",
                    uh->devname, UE_GET_ADDR(ep_addr));
        }

        return (ret);
}

int
usb_write(struct usb_handle *uh, const void *_data, size_t len)
{
        unsigned char *data = (unsigned char *) _data;
        int n, count = 0;
            
        if (uh == NULL)
                return (-1);
    
        if (len == 0) {
       
                n = usb_bulk_write(uh, data, 0);
            
                if (n != 0) {
                        warn("ERROR: n = %d", n);
                        return (-1);
                }
        
                return (0);
        }

        while (len > 0) {
                size_t xfer = (len > 4096) ? 4096 : len;

                n = usb_bulk_write(uh, data, xfer);
        
                if (n != xfer) {
                        warn("ERROR: n = %d", n);
                        return (-1);
                }

                len -= xfer;
                data += xfer;
                count += xfer;
        }

        return (count);
}

int
usb_read(struct usb_handle *uh, void *_data, size_t len)
{
        unsigned char *data = (unsigned char *) _data;
        int n, count = 0;
            
        if (uh == NULL)
                return (-1);
    
        while (len > 0) {
                size_t xfer = (len > 4096) ? 4096 : len;

                DBG("[ usb read %d fd = %d], fname=%s\n", xfer, h->fd, h->devname);
                n = usb_bulk_read(uh, data, xfer);
                DBG("[ usb read %d ] = %d, fname=%s\n", xfer, n, h->devname);
            
                if (n != xfer) {
                        warn("ERROR: n = %d", n);
                        return (-1);
                }

                len -= xfer;
                data += xfer;
                count += xfer;
        }

        return (count);
}

void
usb_kick(struct usb_handle *uh)
{

        usb_close(uh);
}

int
usb_close(struct usb_handle *uh)
{

        if (uh->fd > 0) {
	        close(uh->fd);
    		DBG("[ usb closed %d ]\n", uh->fd);
            uh->fd = -1;
        }

        /* closing endpoints */
        int i = 0;
    
        for ( ; i < 2; ++i) {
                if (uh->ep[i] > 0) {
                        close(uh->ep[i]);
                        uh->ep[i] = -1;
                }
        }
    
        return (0);
}

struct usb_handle *
usb_open(ifc_match_func callback)
{
        return (find_usb_device(callback));
}
