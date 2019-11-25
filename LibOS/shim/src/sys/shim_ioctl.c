/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_ioctl.c
 *
 * Implementation of system call "ioctl".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_fs.h>

#include <pal.h>
#include <pal_error.h>

#include <asm/unistd.h>
#include <errno.h>
#include <asm/ioctl.h>
#include <asm/ioctls.h>
#include <asm/termios.h>
#include <asm/termbits.h>
#include <linux/ioctl.h>
#include <linux/fd.h>
#include <linux/sockios.h>

#define TERM_DEFAULT_IFLAG (ICRNL|IUTF8)
#define TERM_DEFAULT_OFLAG (OPOST|ONLCR)
#define TERM_DEFAULT_CFLAG (B38400|CS8|CREAD)
#define TERM_DEFAULT_LFLAG (ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE|IEXTEN)

static int ioctl_passthru (struct shim_handle * hdl, unsigned int cmd, unsigned long arg);

static int ioctl_termios (struct shim_handle * hdl, unsigned int cmd,
                          unsigned long arg)
{
    if (hdl->type != TYPE_FILE ||
        hdl->info.file.type != FILE_TTY)
        return -ENOTTY;

    if (!arg)
        return -EINVAL;

    switch(cmd) {
        /* <include/asm/termios.h> */
        case TIOCGPGRP:
            *(int *) arg = get_cur_thread()->pgid;
            return 0;

        case TIOCSPGRP:
            return -EINVAL;

        case TCGETS: {
#if 0
            struct termios * termios = (struct termios *) arg;
            termios->c_iflag = TERM_DEFAULT_IFLAG;
            termios->c_oflag = TERM_DEFAULT_OFLAG;
            termios->c_cflag = TERM_DEFAULT_CFLAG;
            termios->c_lflag = TERM_DEFAULT_LFLAG;
            return 0;
#endif
            return -EINVAL;
        }

        case TCSETS:
        case TCSETSW:
        case TCSETSF:
            return -EINVAL;

        /* 0x00005405 TCGETA struct termio * */
        case TCGETA:
        /* 0x00005406 TCSETA const struct termio * */
        case TCSETA:
        /* 0x00005407 TCSETAW const struct termio * */
        case TCSETAW:
        /* 0x00005408 TCSETAF const struct termio * */
        case TCSETAF:
        /* 0x00005409 TCSBRK int */
        case TCSBRK:
        /* 0x0000540A TCXONC int */
        case TCXONC:
        /* 0x0000540B TCFLSH int */
        case TCFLSH:
        /* 0x0000540C TIOCEXCL void */
        case TIOCEXCL:
        /* 0x0000540D TIOCNXCL void */
        case TIOCNXCL:
        /* 0x0000540E TIOCSCTTY int */
        case TIOCSCTTY:
        /* 0x0000540F TIOCGPGRP pid_t * */
        case TIOCOUTQ:
        /* 0x00005412 TIOCSTI const char * */
        case TIOCSTI:
        /* 0x00005413 TIOCGWINSZ struct winsize * */
        case TIOCGWINSZ:
        /* 0x00005415 TIOCMGET int * */
        case TIOCMGET:
        /* 0x00005416 TIOCMBIS const int * */
        case TIOCMBIS:
        /* 0x00005417 TIOCMBIC const int * */
        case TIOCMBIC:
        /* 0x00005418 TIOCMSET const int * */
        case TIOCMSET:
        /* 0x00005419 TIOCGSOFTCAR int * */
        case TIOCGSOFTCAR:
        /* 0x0000541A TIOCSSOFTCAR const int * */
        case TIOCSSOFTCAR:
        /* 0x0000541B FIONREAD int / TIOCINQ int * */
        case TIOCINQ:
        /* 0x0000541C TIOCLINUX const char * */
        case TIOCLINUX:
        /* 0x0000541D TIOCCONS void */
        case TIOCCONS:
        /* 0x0000541E TIOCGSERIAL struct serial_struct * */
        case TIOCGSERIAL:
        /* 0x0000541F TIOCSSERIAL const struct serial_struct * */
        case TIOCSSERIAL:
        /* 0x00005420 TIOCPKT const int * */
        case TIOCPKT:
        /* 0x00005422 TIOCNOTTY void */
        case TIOCNOTTY:
        /* 0x00005423 TIOCSETD const int * */
        case TIOCSETD:
        /* 0x00005424 TIOCGETD int * */
        case TIOCGETD:
        /* 0x00005425 TCSBRKP int */
        case TCSBRKP:
        /* 0x00005453 TIOCSERCONFIG void */
        case TIOCSERCONFIG:
        /* 0x00005454 TIOCSERGWILD int * */
        case TIOCSERGWILD:
        /* 0x00005455 TIOCSERSWILD const int * */
        case TIOCSERSWILD:
        /* 0x00005456 TIOCGLCKTRMIOS struct termios * */
        case TIOCGLCKTRMIOS:
        /* 0x00005457 TIOCSLCKTRMIOS const struct termios * */
        case TIOCSLCKTRMIOS:
        /* 0x00005458 TIOCSERGSTRUCT struct async_struct * */
        case TIOCSERGSTRUCT:
        /* 0x00005459 TIOCSERGETLSR int * */
        case TIOCSERGETLSR:
        /* 0x0000545A TIOCSERGETMULTI struct serial_multiport_struct * */
        case TIOCSERGETMULTI:
        /* 0x0000545B TIOCSERSETMULTI const struct serial_multiport_struct * */
        case TIOCSERSETMULTI:
        default:
            goto passthrough;
    }

 passthrough:
    return -EAGAIN;
}

static int ioctl_fd (struct shim_handle * hdl, unsigned int cmd,
                     unsigned long arg)
{
    // This is just a placeholder function; arguments are not actually used
    // right now
    __UNUSED(hdl);
    __UNUSED(arg);

    switch(cmd) {
        /* <include/linux/fd.h> */

        /* 0x00000000 FDCLRPRM void */
        case FDCLRPRM:
        /* 0x00000001 FDSETPRM const struct floppy_struct * */
        case FDSETPRM:
        /* 0x00000002 FDDEFPRM const struct floppy_struct * */
        case FDDEFPRM:
        /* 0x00000003 FDGETPRM struct floppy_struct * */
        case FDGETPRM:
        /* 0x00000004 FDMSGON void */
        case FDMSGON:
        /* 0x00000005 FDMSGOFF void */
        case FDMSGOFF:
        /* 0x00000006 FDFMTBEG void */
        case FDFMTBEG:
        /* 0x00000007 FDFMTTRK const struct format_descr * */
        case FDFMTTRK:
        /* 0x00000008 FDFMTEND void */
        case FDFMTEND:
        /* 0x0000000A FDSETEMSGTRESH int */
        case FDSETEMSGTRESH:
        /* 0x0000000B FDFLUSH void */
        case FDFLUSH:
        /* 0x0000000C FDSETMAXERRS const struct floppy_max_errors * */
        case FDSETMAXERRS:
        /* 0x0000000E FDGETMAXERRS struct floppy_max_errors * */
        case FDGETMAXERRS:
        /* 0x00000010 FDGETDRVTYP struct { char [16]; } * */
        case FDGETDRVTYP:
        /* 0x00000014 FDSETDRVPRM const struct floppy_drive_params * */
        case FDSETDRVPRM:
        /* 0x00000015 FDGETDRVPRM struct floppy_drive_params * */
        case FDGETDRVPRM:
        /* 0x00000016 FDGETDRVSTAT struct floppy_drive_struct * */
        case FDGETDRVSTAT:
        /* 0x00000017 FDPOLLDRVSTAT struct floppy_drive_struct * */
        case FDPOLLDRVSTAT:
        /* 0x00000018 FDRESET int */
        case FDRESET:
        /* 0x00000019 FDGETFDCSTAT struct floppy_fdc_state * */
        case FDGETFDCSTAT:
        /* 0x0000001B FDWERRORCLR void */
        case FDWERRORCLR:
        /* 0x0000001C FDWERRORGET struct floppy_write_errors * */
        case FDWERRORGET:
        /* 0x0000001E FDRAWCMD struct floppy_raw_cmd *floppy_raw_cmd */
        case FDRAWCMD:
        /* 0x00000028 FDTWADDLE void */
        case FDTWADDLE:
        default:
            goto passthrough;
    }

 passthrough:
    return -EAGAIN;
}

static int ioctl_netdevice (struct shim_handle * hdl, unsigned int cmd,
                            unsigned long arg)
{
    // This is just a placeholder function; arguments are not actually used
    // right now
    __UNUSED(arg);

    if (hdl->type != TYPE_SOCK)
        return -ENOTSOCK;

    struct shim_sock_handle * sock = &hdl->info.sock;

    if (sock->sock_state == SOCK_CREATED) {
        if (sock->sock_type == SOCK_STREAM)
            return -ENOTCONN;
    }

    switch(cmd) {
        /* Socket configuration controls. */
        case SIOCGIFNAME:       /* 0x8910 get iface name */
        case SIOCSIFLINK:       /* 0x8911 set iface channel */
        case SIOCGIFCONF:       /* 0x8912 get iface list */
        case SIOCGIFFLAGS:      /* 0x8913 get flags */
        case SIOCSIFFLAGS:      /* 0x8914 set flags */
        case SIOCGIFADDR:       /* 0x8915 get PA address */
        case SIOCSIFADDR:       /* 0x8916 set PA address */
        case SIOCGIFDSTADDR:    /* 0x8917 get remote PA address */
        case SIOCSIFDSTADDR:    /* 0x8918 set remote PA address */
        case SIOCGIFBRDADDR:    /* 0x8919 get broadcast PA address */
        case SIOCSIFBRDADDR:    /* 0x891a set broadcast PA address */
        case SIOCGIFNETMASK:    /* 0x891b get network PA mask */
        case SIOCSIFNETMASK:    /* 0x891c set network PA mask */
        case SIOCGIFMETRIC:     /* 0x891d get metric */
        case SIOCSIFMETRIC:     /* 0x891e set metric */
        case SIOCGIFMEM:        /* 0x891f get memory address (BSD) */
        case SIOCSIFMEM:        /* 0x8920 set memory address (BSD) */
        case SIOCGIFMTU:        /* 0x8921 get MTU size */
        case SIOCSIFMTU:        /* 0x8922 set MTU size */
        case SIOCSIFNAME:       /* 0x8923 set interface name */
        case SIOCSIFHWADDR:     /* 0x8924 set hardware address */
        case SIOCGIFENCAP:      /* 0x8925 get/set encapsulations       */
        case SIOCSIFENCAP:      /* 0x8926 */
        case SIOCGIFHWADDR:     /* 0x8927 Get hardware address */
        case SIOCGIFSLAVE:      /* 0x8929 Driver slaving support */
        case SIOCSIFSLAVE:      /* 0x8930 */
        case SIOCADDMULTI:      /* 0x8931 Multicast address lists */
        case SIOCDELMULTI:      /* 0x8932 */
        case SIOCGIFINDEX:      /* 0x8933 name -> if_index mapping */
        /* SIOGIFINDEX = SIOCGIFINDEX misprint compatibility :-) */
        case SIOCSIFPFLAGS:     /* 0x8934 set/get extended flags set */
        case SIOCGIFPFLAGS:     /* 0x8935 */
        case SIOCDIFADDR:       /* 0x8936 delete PA address */
        case SIOCSIFHWBROADCAST: /* 0x8937 set hardware broadcast addr */
        case SIOCGIFCOUNT:      /* 0x8938 get number of devices */
        case SIOCGIFBR:         /* 0x8940 Bridging support */
        case SIOCSIFBR:         /* 0x8941 Set bridging options  */
        case SIOCGIFTXQLEN:     /* 0x8942 Get the tx queue length */
        case SIOCSIFTXQLEN:     /* 0x8943 Set the tx queue length  */
        default:
            goto passthrough;
    }

 passthrough:
    return -EAGAIN;
}

void signal_io (IDTYPE target, void *arg)
{
    // Kept for compatibility with signal_itimer
    __UNUSED(arg);

    debug("detecting input, signaling thread %u\n", target);

    struct shim_thread * thread = lookup_thread(target);
    if (!thread)
        return;

    append_signal(thread, SIGIO, NULL, true);
}

int shim_do_ioctl (int fd, int cmd, unsigned long arg)
{
    struct shim_handle * hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -EAGAIN;
    switch(cmd) {
        /* <include/asm/termios.h> */
        case TCGETS:
        case TCSETS:
        case TCSETSW:
        case TCSETSF:
        case TCGETA:
        case TCSETA:
        case TCSETAW:
        case TCSETAF:
        case TCSBRK:
        case TCXONC:
        case TCFLSH:
        case TIOCEXCL:
        case TIOCNXCL:
        case TIOCSCTTY:
        case TIOCGPGRP:
        case TIOCSPGRP:
        case TIOCOUTQ:
        case TIOCSTI:
        case TIOCGWINSZ:
        case TIOCMGET:
        case TIOCMBIS:
        case TIOCMBIC:
        case TIOCMSET:
        case TIOCGSOFTCAR:
        case TIOCSSOFTCAR:
        /* case TIOCINQ = FIONREAD */
        case TIOCLINUX:
        case TIOCCONS:
        case TIOCGSERIAL:
        case TIOCSSERIAL:
        case TIOCPKT:
        case TIOCNOTTY:
        case TIOCSETD:
        case TIOCGETD:
        case TCSBRKP:
            ret = ioctl_termios(hdl, cmd, arg);
            break;
        case FIONBIO:
            if (hdl->fs && hdl->fs->fs_ops &&
                hdl->fs->fs_ops->setflags)
                hdl->fs->fs_ops->setflags(hdl, hdl->flags | O_NONBLOCK);
            hdl->flags |= O_NONBLOCK;
            ret = 0;
            break;
        case FIONCLEX:
            hdl->flags &= ~FD_CLOEXEC;
            ret = 0;
            break;
        case FIOCLEX:
            hdl->flags |= FD_CLOEXEC;
            ret = 0;
            break;
        case FIOASYNC:
            ret = install_async_event(hdl->pal_handle, 0, &signal_io, NULL);
            break;
        case TIOCSERCONFIG:
        case TIOCSERGWILD:
        case TIOCSERSWILD:
        case TIOCGLCKTRMIOS:
        case TIOCSLCKTRMIOS:
        case TIOCSERGSTRUCT:
        case TIOCSERGETLSR:
        case TIOCSERGETMULTI:
        case TIOCSERSETMULTI:
            ret = ioctl_termios(hdl, cmd, arg);
            break;

        case FDCLRPRM:
        case FDSETPRM:
        case FDDEFPRM:
        case FDGETPRM:
        case FDMSGON:
        case FDMSGOFF:
        case FDFMTBEG:
        case FDFMTTRK:
        case FDFMTEND:
        case FDSETEMSGTRESH:
        case FDFLUSH:
        case FDSETMAXERRS:
        case FDGETMAXERRS:
        case FDGETDRVTYP:
        case FDSETDRVPRM:
        case FDGETDRVPRM:
        case FDGETDRVSTAT:
        case FDPOLLDRVSTAT:
        case FDRESET:
        case FDGETFDCSTAT:
        case FDWERRORCLR:
        case FDWERRORGET:
        case FDRAWCMD:
        case FDTWADDLE:
            ret = ioctl_fd(hdl, cmd, arg);
            break;

        case FIONREAD: {
            struct shim_mount * fs = hdl->fs;
            int size = 0;
            int offset = 0;

            if (!fs || !fs->fs_ops) {
                ret = -EACCES;
                break;
            }

            if (fs->fs_ops->hstat) {
                struct stat stat;
                ret = fs->fs_ops->hstat(hdl, &stat);
                if (ret < 0)
                    break;

                size = stat.st_size;
                goto done_fioread;
            }

            if (hdl->pal_handle) {
                PAL_STREAM_ATTR attr;
                if (!DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr)) {
                    ret = -PAL_ERRNO;
                    break;
                }
                size = attr.pending_size;
                goto done_fioread;
            }

done_fioread:
            if (fs->fs_ops->seek) {
                ret = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
                if (ret < 0)
                    break;
                offset = ret;
            }

            *(int *) arg = size - offset;
            ret = 0;
            break;
        }

        /* Socket configuration controls. */
        case SIOCGIFNAME:       /* 0x8910 get iface name */
        case SIOCSIFLINK:       /* 0x8911 set iface channel */
        case SIOCGIFCONF:       /* 0x8912 get iface list */
        case SIOCGIFFLAGS:      /* 0x8913 get flags */
        case SIOCSIFFLAGS:      /* 0x8914 set flags */
        case SIOCGIFADDR:       /* 0x8915 get PA address */
        case SIOCSIFADDR:       /* 0x8916 set PA address */
        case SIOCGIFDSTADDR:    /* 0x8917 get remote PA address */
        case SIOCSIFDSTADDR:    /* 0x8918 set remote PA address */
        case SIOCGIFBRDADDR:    /* 0x8919 get broadcast PA address */
        case SIOCSIFBRDADDR:    /* 0x891a set broadcast PA address */
        case SIOCGIFNETMASK:    /* 0x891b get network PA mask */
        case SIOCSIFNETMASK:    /* 0x891c set network PA mask */
        case SIOCGIFMETRIC:     /* 0x891d get metric */
        case SIOCSIFMETRIC:     /* 0x891e set metric */
        case SIOCGIFMEM:        /* 0x891f get memory address (BSD) */
        case SIOCSIFMEM:        /* 0x8920 set memory address (BSD) */
        case SIOCGIFMTU:        /* 0x8921 get MTU size */
        case SIOCSIFMTU:        /* 0x8922 set MTU size */
        case SIOCSIFNAME:       /* 0x8923 set interface name */
        case SIOCSIFHWADDR:     /* 0x8924 set hardware address */
        case SIOCGIFENCAP:      /* 0x8925 get/set encapsulations       */
        case SIOCSIFENCAP:      /* 0x8926 */
        case SIOCGIFHWADDR:     /* 0x8927 Get hardware address */
        case SIOCGIFSLAVE:      /* 0x8929 Driver slaving support */
        case SIOCSIFSLAVE:      /* 0x8930 */
        case SIOCADDMULTI:      /* 0x8931 Multicast address lists */
        case SIOCDELMULTI:      /* 0x8932 */
        case SIOCGIFINDEX:      /* 0x8933 name -> if_index mapping */
        /* SIOGIFINDEX = SIOCGIFINDEX misprint compatibility :-) */
        case SIOCSIFPFLAGS:     /* 0x8934 set/get extended flags set */
        case SIOCGIFPFLAGS:     /* 0x8935 */
        case SIOCDIFADDR:       /* 0x8936 delete PA address */
        case SIOCSIFHWBROADCAST: /* 0x8937 set hardware broadcast addr */
        case SIOCGIFCOUNT:      /* 0x8938 get number of devices */
        case SIOCGIFBR:         /* 0x8940 Bridging support */
        case SIOCSIFBR:         /* 0x8941 Set bridging options  */
        case SIOCGIFTXQLEN:     /* 0x8942 Get the tx queue length */
        case SIOCSIFTXQLEN:     /* 0x8943 Set the tx queue length  */
            ret = ioctl_netdevice(hdl, cmd, arg);
            break;

        default:
            ret = ioctl_passthru(hdl, cmd, arg);
            break;
    }

    put_handle(hdl);
    return ret;
}

#define DUMMY_IOCTL_PRINT   _IOR('p', 0x01, struct dummy_print)
struct dummy_print {
    const char * str;
    unsigned long size;
};

/* Dmitrii Kuvaiskii: list of ioctls for North Cove FPGA driver */
#define FPGA_MAGIC 0xB5
#define FPGA_BASE  0x00
#define PORT_BASE  0x40
#define FME_BASE   0x80

#define FPGA_GET_API_VERSION        _IO(FPGA_MAGIC, FPGA_BASE + 0)
#define FPGA_CHECK_EXTENSION        _IO(FPGA_MAGIC, FPGA_BASE + 1)
#define FPGA_PORT_RESET             _IO(FPGA_MAGIC, PORT_BASE + 0)
#define FPGA_PORT_GET_INFO          _IO(FPGA_MAGIC, PORT_BASE + 1)
#define FPGA_PORT_GET_REGION_INFO   _IO(FPGA_MAGIC, PORT_BASE + 2)
#define FPGA_PORT_DMA_MAP           _IO(FPGA_MAGIC, PORT_BASE + 3)
#define FPGA_PORT_DMA_UNMAP         _IO(FPGA_MAGIC, PORT_BASE + 4)
#define FPGA_PORT_UMSG_ENABLE       _IO(FPGA_MAGIC, PORT_BASE + 5)
#define FPGA_PORT_UMSG_DISABLE      _IO(FPGA_MAGIC, PORT_BASE + 6)
#define FPGA_PORT_UMSG_SET_MODE     _IO(FPGA_MAGIC, PORT_BASE + 7)
#define FPGA_PORT_UMSG_SET_BASE_ADDR    _IO(FPGA_MAGIC, PORT_BASE + 8)
#define FPGA_PORT_ERR_SET_IRQ       _IO(FPGA_MAGIC, PORT_BASE + 9)
#define FPGA_PORT_UAFU_SET_IRQ      _IO(FPGA_MAGIC, PORT_BASE + 10)
#define FPGA_PORT_UAFU_MMAP         _IO(FPGA_MAGIC, PORT_BASE + 11)
#define FPGA_PORT_UAFU_UNMAP        _IO(FPGA_MAGIC, PORT_BASE + 12)
#define FPGA_FME_PORT_PR            _IO(FPGA_MAGIC, FME_BASE + 0)
#define FPGA_FME_PORT_RELEASE       _IO(FPGA_MAGIC, FME_BASE + 1)
#define FPGA_FME_PORT_ASSIGN        _IO(FPGA_MAGIC, FME_BASE + 2)
#define FPGA_FME_GET_INFO           _IO(FPGA_MAGIC, FME_BASE + 3)
#define FPGA_FME_ERR_SET_IRQ        _IO(FPGA_MAGIC, FME_BASE + 4)

struct fpga_port_info {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u32 capability;   /* The capability of port device */
    __u32 num_regions;  /* The number of supported regions */
    __u32 num_umsgs;    /* The number of allocated umsgs */
    __u32 num_uafu_irqs;    /* The number of uafu interrupts */
};

struct fpga_port_region_info {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Access permission */
    __u32 index;        /* Region index */
    __u32 padding;
    __u64 size;         /* Region size (bytes) */
    __u64 offset;       /* Region offset from start of device fd */
};

struct fpga_port_dma_map {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u64 user_addr;        /* Process virtual address */
    __u64 length;           /* Length of mapping (bytes)*/
    __u64 iova;             /* IO virtual address */
};

struct fpga_port_dma_unmap {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u64 iova;     /* IO virtual address */
};

struct fpga_port_umsg_cfg {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u32 hint_bitmap;  /* UMSG Hint Mode Bitmap */
};

struct fpga_port_umsg_base_addr {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u64 iova;     /* IO virtual address */
};

struct fpga_port_err_irq_set {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __s32 evtfd;        /* Eventfd handler */
};

struct fpga_port_uafu_irq_set {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u32 start;        /* First irq number */
    __u32 count;        /* The number of eventfd handler */
    __s32 evtfd[8];     /* Eventfd handler; assume no more than 8 for simplicity */
};

struct fpga_port_uafu_mmap {
    __u32 argsz;        /* Structure length, ignored */
    __u32 flags;        /* MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_HUGETLB | MAP_1G_HUGEPAGE */
    __u64 addr;         /* Always zero, ignored */
    __u64 len;          /* Length of DMA region to allocate in untrusted memory */
    __u64 local_addr;   /* Output address of the allocated DMA region in untrusted memory */
};

struct fpga_port_uafu_unmap {
    __u32 argsz;        /* Structure length, ignored */
    __u32 flags;        /* Flags, ignored */
    __u64 addr;         /* Base address of DMA region allocated in untrusted memory */
    __u64 len;          /* Length of DMA region allocated in untrusted memory */
};

struct fpga_fme_port_pr {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u32 port_id;
    __u32 buffer_size;
    __u64 buffer_address;   /* Userspace address to the buffer for PR */
    __u64 status;       /* HW error code if ioctl returns -EIO */
};

struct fpga_fme_port_release {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u32 port_id;
};

struct fpga_fme_port_assign {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u32 port_id;
};

struct fpga_fme_info {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __u32 capability;   /* The capability of FME device */
};

struct fpga_fme_err_irq_set {
    __u32 argsz;        /* Structure length */
    __u32 flags;        /* Zero for now */
    __s32 evtfd;        /* Eventfd handler */
};


static int ioctl_passthru (struct shim_handle * hdl, unsigned int cmd, unsigned long arg) {
    PAL_ARG* pal_arg = NULL;
    PAL_NUM ninputs = 0, noutputs = 0;
    PAL_ARG* inputs  = NULL;
    PAL_ARG* outputs = NULL;

    // Don't change these macros

    #define SET_ARG_TYPE(type)                              \
        do {                                                \
            pal_arg = __alloca(sizeof(PAL_ARG));            \
            pal_arg->val  = (PAL_PTR) arg;                  \
            pal_arg->size = sizeof(type);                   \
            pal_arg->off  = 0;                              \
        } while (0)


    #define SET_NOUTPUTS(num)                               \
        do {                                                \
            outputs = __alloca(sizeof(PAL_ARG) * (num));    \
        } while (0)

    #define ADD_OUTPUT_SIZE(type, field, fsize)             \
        do {                                                \
            type* __a = (void *) arg;                       \
            outputs[noutputs].val  = (PAL_PTR) __a->field;  \
            outputs[noutputs].size = (fsize);               \
            outputs[noutputs].off  = offsetof(type, field); \
            noutputs++;                                     \
        } while (0)

    #define SET_NINPUTS(num)                                \
        do {                                                \
            inputs = __alloca(sizeof(PAL_ARG) * (num));     \
        } while (0)

    #define ADD_INPUT_SIZE(type, field, fsize)              \
        do {                                                \
            type* __a = (void *) arg;                       \
            inputs[ninputs].val  = (PAL_PTR) __a->field;    \
            inputs[ninputs].size = (fsize);                 \
            inputs[ninputs].off  = offsetof(type, field);   \
            ninputs++;                                      \
        } while (0)


    // List the all ioctl opcodes allowed for passthrough
    switch(cmd) {
        // This is an example: DUMMY_IOCTL_PRINT will print out the string
        // in the argument to the kernel log.
        case DUMMY_IOCTL_PRINT: {
            struct dummy_print* __arg = (void *) arg;
            SET_ARG_TYPE(struct dummy_print);
            SET_NOUTPUTS(1);
            ADD_OUTPUT_SIZE(struct dummy_print, str, __arg->size);
            // Specify input size if necessary
            break;
        }

        // Dmitrii Kuvaiskii: list of ioctls for North Cove FPGA driver
        case FPGA_GET_API_VERSION:
        case FPGA_CHECK_EXTENSION:
        case FPGA_PORT_RESET:
        case FPGA_PORT_UMSG_ENABLE:
        case FPGA_PORT_UMSG_DISABLE:
            break;

        case FPGA_PORT_GET_INFO: {
            struct fpga_port_info* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_port_info);
            break;
        }

        case FPGA_PORT_GET_REGION_INFO: {
            struct fpga_port_region_info* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_port_region_info);
            break;
        }

        case FPGA_PORT_DMA_MAP: {
            struct fpga_port_dma_map* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_port_dma_map);
            /* TODO: This ioctl fails because user_addr is in enclave space
             *       not available for the kernel driver! */
            debug("ioctl(FPGA_PORT_DMA_MAP): user_addr=%p length=%lu\n",
                  __arg->user_addr, __arg->length);
            break;
        }

        case FPGA_PORT_DMA_UNMAP: {
            struct fpga_port_dma_unmap* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_port_dma_unmap);
            break;
        }

        case FPGA_PORT_UMSG_SET_MODE: {
            struct fpga_port_umsg_cfg* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_port_umsg_cfg);
            break;
        }

        case FPGA_PORT_UMSG_SET_BASE_ADDR: {
            struct fpga_port_umsg_base_addr* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_port_umsg_base_addr);
            break;
        }

        case FPGA_PORT_ERR_SET_IRQ: {
            struct fpga_port_err_irq_set* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_port_err_irq_set);
            break;
        }

        case FPGA_PORT_UAFU_SET_IRQ: {
            struct fpga_port_uafu_irq_set* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_port_uafu_irq_set);
            break;
        }

        case FPGA_PORT_UAFU_MMAP: {
            /* special case: instead of ioctl, allocate untrusted memory */
#define PAL_ALLOC_DMAREGION   0x4000
            struct fpga_port_uafu_mmap* __arg = (void *) arg;
            __arg->addr = 0x0UL;
            void* ret = (void *) DkVirtualMemoryAlloc(/* addr */ (void*)__arg->addr,
                                                      /* size */ __arg->len,
                                                      /* alloc_type */ PAL_ALLOC_DMAREGION,
                                                      /* prot abused as flags */ __arg->flags);
            if (!ret) {
                __arg->local_addr = 0;
                return -ENOMEM;
            }
            __arg->local_addr = (uint64_t) ret;
            return 0;
        }

        case FPGA_PORT_UAFU_UNMAP: {
            /* special case: instead of ioctl, deallocate untrusted memory */
            struct fpga_port_uafu_unmap* __arg = (void *) arg;
            DkVirtualMemoryFree((void*)__arg->addr, __arg->len);
            return 0;
        }

        case FPGA_FME_PORT_PR: {
            struct fpga_fme_port_pr* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_fme_port_pr);
            break;
        }

        case FPGA_FME_PORT_RELEASE: {
            struct fpga_fme_port_release* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_fme_port_release);
            break;
        }

        case FPGA_FME_PORT_ASSIGN: {
            struct fpga_fme_port_assign* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_fme_port_assign);
            break;
        }

        case FPGA_FME_GET_INFO: {
            struct fpga_fme_info* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_fme_info);
            break;
        }

        case FPGA_FME_ERR_SET_IRQ: {
            struct fpga_fme_err_irq_set* __arg = (void *) arg;
            SET_ARG_TYPE(struct fpga_fme_err_irq_set);
            break;
        }

        default:
            return -ENOSYS;
    }

    PAL_NATIVE_ERRNO = 0;
    PAL_NUM retval = DkHostExtensionCall(hdl->pal_handle, cmd, pal_arg, noutputs, outputs,
            ninputs, inputs);
    return (PAL_NATIVE_ERRNO == 0) ? (int) retval : -PAL_ERRNO;
}
