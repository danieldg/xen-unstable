/* config.h.  Generated by configure.  */
//  Copyright (C) 2001  MandrakeSoft S.A.
//
//    MandrakeSoft S.A.
//    43, rue d'Aboukir
//    75002 Paris - France
//    http://www.linux-mandrake.com/
//    http://www.mandrakesoft.com/
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

//
// config.h.in is distributed in the source TAR file.  When you run
// the configure script, it generates config.h with some changes
// according to your build environment.  For example, in config.h.in,
// SIZEOF_UNSIGNED_CHAR is set to 0.  When configure produces config.h
// it will change "0" to the detected value for your system.
//
// config.h contains ONLY preprocessor #defines and a few typedefs.
// It must be included by both C and C++ files, so it must not
// contain anything language dependent such as a class declaration.
//

#ifdef _BX_CONFIG_H_
#else
#define _BX_CONFIG_H_ 1

///////////////////////////////////////////////////////////////////
// USER CONFIGURABLE OPTIONS : EDIT ONLY OPTIONS IN THIS SECTION //
///////////////////////////////////////////////////////////////////


#if 1
// quit_sim is defined in gui/siminterface.h
#define BX_EXIT(x)  SIM->quit_sim (x)
#else
// provide the real main and the usual exit.
#define BX_EXIT(x)  ::exit(x)
#endif

#define BX_USE_CONFIG_INTERFACE 0
#define BX_USE_VMX 1

// I have tested the following combinations:
//  * processors=1, bootstrap=0, ioapic_id=1   (uniprocessor system)
//  * processors=2, bootstrap=0, ioapic_id=2
//  * processors=4, bootstrap=2, ioapic_id=4
#define BX_SMP_PROCESSORS 1
#define BX_BOOTSTRAP_PROCESSOR 0
// choose IOAPIC id to be equal to the number of processors.  This leaves
// one space for each processor to have an ID, starting with 0.
#define BX_IOAPIC_DEFAULT_ID 1

#define BX_ADDRESS_SPACES 1
// controls how many instances of BX_MEM_C are created.  For
// SMP, use several processors with one shared memory space.
// For cosimulation, you could use two processors and two address
// spaces.

#define BX_SUPPORT_APIC 0
// include in APIC models, required for a multiprocessor system.

#if (BX_SMP_PROCESSORS>1 && !BX_SUPPORT_APIC)
#error For multiprocessor simulation, BX_SUPPORT_APIC is required.
#endif

#define BX_DEBUG_LINUX 0
// if simulating Linux, this provides a few more debugging options
// such as tracing all system calls.

#define HAVE_LIBREADLINE 0
#define HAVE_READLINE_HISTORY_H 1
// adds support for the GNU readline library in the debugger command
// prompt.

#define HAVE_LOCALE_H 0
// Define to 1 if you have <locale.h>

// I rebuilt the code which provides timers to IO devices.
// Setting this to 1 will introduce a little code which
// will panic out if cases which shouldn't happen occur.
// Set this to 0 for optimal performance.
#define BX_TIMER_DEBUG 1

// Settable A20 line.  For efficiency, you can disable
// having a settable A20 line, eliminating conditional
// code for every physical memory access.  You'll have
// to tell your software not to mess with the A20 line,
// and accept it as always being on if you change this.
//   1 = use settable A20 line. (normal)
//   0 = A20 is like the rest of the address lines

#define BX_SUPPORT_A20 1

// Processor Instructions Per Second
// To find out what value to use for the 'ips' directive
// in your '.bochsrc' file, set BX_SHOW_IPS to 1, and
// run the software in bochs you plan to use most.  Bochs
// will print out periodic IPS ratings.  This will change
// based on the processor mode at the time, and various
// other factors.  You'll get a reasonable estimate though.
// When you're done, reset BX_SHOW_IPS to 0, do a
// 'make all-clean', then 'make' again.

#define BX_SHOW_IPS         0


#if (BX_SHOW_IPS) && defined(__MINGW32__)
#define        SIGALRM         14
#endif

// Paging Options:
// ---------------
// Support Paging mechanism.
//   0 = don't support paging at all (DOS & Minix don't require it)
//   1 = support paging.  (Most other OS's require paging)
// Use Translation Lookaside Buffer (TLB) for caching
// paging translations.  This will make paging mode
// more efficient.  If you're OS doesn't use paging,
// then you won't need either.
//   1 = Use a TLB for effiency
//   0 = don't use a TLB, walk the page tables for every access
// BX_TLB_SIZE: Number of entries in TLB
// BX_TLB_INDEX_OF(lpf): This macro is passed the linear page frame
//   (top 20 bits of the linear address.  It must map these bits to
//   one of the TLB cache slots, given the size of BX_TLB_SIZE.
//   There will be a many-to-one mapping to each TLB cache slot.
//   When there are collisions, the old entry is overwritten with
//   one for the newest access.

#define BX_SUPPORT_PAGING     1
#define BX_USE_TLB 1

#define BX_TLB_SIZE 1024
#define BX_TLB_INDEX_OF(lpf) (((lpf) & 0x003ff000) >> 12)

#define BX_USE_QUICK_TLB_INVALIDATE 0

// Compile in support for DMA & FLOPPY IO.  You'll need this
// if you plan to use the floppy drive emulation.  But if
// you're environment doesn't require it, you can change
// it to 0.

#define BX_DMA_FLOPPY_IO 1


// Default number of Megs of memory to emulate.  The
// 'megs:' directive in the '.bochsrc' file overrides this,
// allowing per-run settings.

#define BX_DEFAULT_MEM_MEGS 4


// CPU level emulation.  Default level is set in
// the configure script.  BX_CPU_LEVEL defines the CPU level
// to emulate.  BX_CPU_LEVEL_HACKED is a hack to define the
// level of some integer instructions, so they can be tested
// before the rest of the emulation is up to that level.

#define BX_CPU_LEVEL 5
#define BX_CPU_LEVEL_HACKED 5

// emulate x86-64 instruction set?
#define BX_SUPPORT_X86_64 0

// Virtual 8086 mode emulation.
//   1 = compile in support for v8086 mode.
//   0 = don't compile in support for v8086 mode.
#define BX_SUPPORT_V8086_MODE 1

// Defines if the simulation should reset on triple fault
// if set to 0, the simulation will panic.
#define BX_RESET_ON_TRIPLE_FAULT 1

// Support shadowing of ROM from C0000 to FFFFF.
// This allows that region to be written to.
#define BX_SHADOW_RAM 0

// Number of CMOS registers
#define BX_NUM_CMOS_REGS 64
//#define BX_NUM_CMOS_REGS 128

// Use Greg Alexander's new PIT model (summer 2001) instead of the original.
#define BX_USE_NEW_PIT 1

#define BX_USE_SLOWDOWN_TIMER 0
#define BX_HAVE_SLEEP 1
#define BX_HAVE_MSLEEP 0
#define BX_HAVE_USLEEP 1
#define BX_HAVE_NANOSLEEP 1
#define BX_HAVE_ABORT 1
#define BX_HAVE_SOCKLEN_T 1
#define BX_HAVE_SOCKADDR_IN_SIN_LEN 0
#define BX_HAVE_GETTIMEOFDAY 1
#if defined(WIN32)
#define BX_HAVE_REALTIME_USEC 1
#else
#define BX_HAVE_REALTIME_USEC (BX_HAVE_GETTIMEOFDAY)
#endif
#define BX_HAVE_MKSTEMP 1
#define BX_HAVE_SYS_MMAN_H 1
#define BX_HAVE_XPM_H 1
#define BX_HAVE_TIMELOCAL 1
#define BX_HAVE_GMTIME 1
#define BX_HAVE_MKTIME 1

// This turns on Roland Mainz's idle hack.  Presently it is specific to the X11
// gui. If people try to enable it elsewhere, give a compile error after the
// gui definition so that they don't waste their time trying.
#define BX_USE_IDLE_HACK 0

// Minimum Emulated IPS.
// This is used in the realtime PIT as well as for checking the
// IPS value set in the config file.
#define BX_MIN_IPS 200000

// Use Static Member Funtions to eliminate 'this' pointer passing
// If you want the efficiency of 'C', you can make all the
// members of the C++ CPU class to be static.
// This defaults to 1 since it should improve performance, but when
// SMP mode is enabled, it will be turned off by configure.

#define BX_USE_CPU_SMF 1

// Use static member functions in IO DEVice emulation modules.
// For efficiency, use C like functions for IO handling,
// and declare a device instance at compile time,
// instead of using 'new' and storing the pointer.  This
// eliminates some overhead, especially for high-use IO
// devices like the disk drive.
//   1 = Use static member efficiency (normal)
//   0 = Use nonstatic member functions (use only if you need
//       multiple instances of a device class

#define BX_USE_HD_SMF      1  // Hard drive
#define BX_USE_BIOS_SMF    1  // BIOS
#define BX_USE_CMOS_SMF    1  // CMOS
#define BX_USE_DMA_SMF     1  // DMA
#define BX_USE_FD_SMF      1  // Floppy
#define BX_USE_KEY_SMF     1  // Keyboard
#define BX_USE_PAR_SMF     1  // Parallel
#define BX_USE_PIC_SMF     1  // PIC
#define BX_USE_PIT_SMF     1  // PIT
#define BX_USE_SER_SMF     1  // Serial
#define BX_USE_UM_SMF      1  // Unmapped
#define BX_USE_VGA_SMF     1  // VGA
#define BX_USE_SB16_SMF    1  // Sound (SB 16)
#define BX_USE_DEV_SMF     1  // System Devices (port92)
#define BX_USE_PCI_SMF     1  // PCI
#define BX_USE_P2I_SMF     1  // PCI-to-ISA bridge
#define BX_USE_PCIVGA_SMF  1  // PCI-VGA
#define BX_USE_PCIUSB_SMF  1  // USB hub
#define BX_USE_NE2K_SMF    1  // NE2K
#define BX_USE_EFI_SMF     1  // External FPU IRQ
#define BX_USE_GAME_SMF    1  // Gameport

#define BX_PLUGINS 0
#define BX_HAVE_DLFCN_H 1

#if BX_PLUGINS && \
  (   !BX_USE_HD_SMF || !BX_USE_BIOS_SMF || !BX_USE_CMOS_SMF \
   || !BX_USE_DMA_SMF || !BX_USE_FD_SMF || !BX_USE_KEY_SMF \
   || !BX_USE_PAR_SMF || !BX_USE_PIC_SMF || !BX_USE_PIT_SMF \
   || !BX_USE_SER_SMF || !BX_USE_UM_SMF || !BX_USE_VGA_SMF \
   || !BX_USE_SB16_SMF || !BX_USE_DEV_SMF || !BX_USE_PCI_SMF \
   || !BX_USE_P2I_SMF || !BX_USE_PCIVGA_SMF || !BX_USE_PCIUSB_SMF \
   || !BX_USE_NE2K_SMF || !BX_USE_EFI_SMF || !BX_USE_GAME_SMF)
#error You must use SMF to have plugins
#endif

#define BX_SUPPORT_SB16 0
#define BX_SUPPORT_GAME 0

#if BX_SUPPORT_SB16
// Use virtual methods for the sound output functions
#define BX_USE_SOUND_VIRTUAL  1
// Determines which sound output class is to be used.
// Currently the following are available:
//    bx_sound_linux_c      Output for Linux, to /dev/dsp and /dev/midi00
//    bx_sound_windows_c    Output for Windows midi and wave mappers
//    bx_sound_output_c     Dummy functions, no output
#define BX_SOUND_OUTPUT_C  bx_sound_output_c
#endif

#define USE_RAW_SERIAL 0

#define BX_USE_SPECIFIED_TIME0 0

// This enables writing to port 0xe9 and the output
// is sent to the console.  Reading from port 0xe9
// will return 0xe9 to let you know this is available.
// Leave this 0 unless you have a reason to use it.
#define BX_PORT_E9_HACK 1

#define BX_GDBSTUB 0

// This option enables compressed (zlib) hd support
#define BX_COMPRESSED_HD_SUPPORT 0
#define BX_HAVE_ZLIB 1

#if BX_COMPRESSED_HD_SUPPORT && !BX_HAVE_ZLIB
#error You must have zlib to enable compressed hd support
#endif

// This option defines the number of supported ATA channels.
// There are up to two drives per ATA channel.
#define BX_MAX_ATA_CHANNEL 4

#if (BX_MAX_ATA_CHANNEL>4 || BX_MAX_ATA_CHANNEL<1)
#  error "BX_MAX_ATA_CHANNEL should be between 1 and 4"
#endif

// =================================================================
// BEGIN: OPTIONAL DEBUGGER SECTION
//
// These options are only used if you compile in support for the
// native command line debugging environment.  Typically, the debugger
// is not used, and this section can be ignored.
// =================================================================

#define BX_MAX_DIRTY_PAGE_TABLE_MEGS 1024

// Compile in support for virtual/linear/physical breakpoints.
// Set to 1, only those you need.  Recommend using only linear
// breakpoints, unless you need others.  Less supported means
// slightly faster execution time.
#define BX_DBG_SUPPORT_VIR_BPOINT 1
#define BX_DBG_SUPPORT_LIN_BPOINT 1
#define BX_DBG_SUPPORT_PHY_BPOINT 1

// You need only define one initial breakpoint into each
// cpu simulator (emulator) here.  Each simulator sets callbacks
// and variables which the debugger uses from then on.
#define BX_SIM1_INIT bx_dbg_init_cpu_mem_env0
#ifndef BX_SIM2_INIT
#define BX_SIM2_INIT bx_dbg_init_cpu_mem_env1
#endif
//#define BX_SIM2_INIT sim2_init

// max number of virtual/linear/physical breakpoints handled
#define BX_DBG_MAX_VIR_BPOINTS 10
#define BX_DBG_MAX_LIN_BPOINTS 10
#define BX_DBG_MAX_PHY_BPOINTS 10

// max file pathname size for debugger commands
#define BX_MAX_PATH     256
// max nesting level for debug scripts including other scripts
#define BX_INFILE_DEPTH  10
// use this command to include (nest) debug scripts
#define BX_INCLUDE_CMD   "source"

// Use either 32 or 64 bit instruction counter for
// debugger purposes.  Uncomment one of these.
//#define BX_DBG_ICOUNT_SIZE   32
#define BX_DBG_ICOUNT_SIZE   64

// Make a call to command line debugger extensions.  If set to 1,
// a call is made.  An external routine has a chance to process
// the command.  If it does, than the debugger ignores the command.
#define BX_DBG_EXTENSIONS 0

// =================================================================
// END: OPTIONAL DEBUGGER SECTION
// =================================================================


//////////////////////////////////////////////////////////////////////
// END OF USER CONFIGURABLE OPTIONS : DON'T EDIT ANYTHING BELOW !!! //
// THIS IS GENERATED BY THE ./configure SCRIPT                      //
//////////////////////////////////////////////////////////////////////


#define BX_WITH_X11 1
#define BX_WITH_BEOS 0
#define BX_WITH_WIN32 0
#define BX_WITH_MACOS 0
#define BX_WITH_CARBON 0
#define BX_WITH_NOGUI 0
#define BX_WITH_TERM 0
#define BX_WITH_RFB 0
#define BX_WITH_AMIGAOS 0
#define BX_WITH_SDL 0
#define BX_WITH_SVGA 0
#define BX_WITH_WX 0

// add special export symbols for win32 DLL building.  The main code must
// have __declspec(dllexport) on variables, functions, or classes that the
// plugins can access.  The plugins should #define PLUGGABLE which will
// activate the __declspec(dllimport) instead.
#if defined(WIN32) || defined(__CYGWIN__)
#  if BX_PLUGINS && defined(BX_PLUGGABLE)
//   #warning I will import DLL symbols from Bochs main program.
#    define BOCHSAPI __declspec(dllimport)
#  else
//   #warning I will export DLL symbols.
#    define BOCHSAPI __declspec(dllexport)
#  endif
#endif
#ifndef BOCHSAPI
#  define BOCHSAPI
#endif

#if defined(__CYGWIN__)
// Make BOCHSAPI_CYGONLY exactly the same as BOCHSAPI.  This symbol
// will be used for any cases where Cygwin requires a special tag
// but VC++ does not.
#define BOCHSAPI_CYGONLY BOCHSAPI
#else
// define the symbol to be empty
#define BOCHSAPI_CYGONLY /*empty*/
#endif

#define BX_DEFAULT_CONFIG_INTERFACE "defined_by_configure"
#define BX_DEFAULT_DISPLAY_LIBRARY "defined_by_configure"

// Roland Mainz's idle hack is presently specific to X11. If people try to
// enable it elsewhere, give a compile error so that they don't waste their
// time trying.
#if (BX_USE_IDLE_HACK && !BX_WITH_X11)
#  error IDLE_HACK will only work with the X11 gui. Correct configure args and retry.
#endif

#define WORDS_BIGENDIAN 0

#define SIZEOF_UNSIGNED_CHAR 1
#define SIZEOF_UNSIGNED_SHORT 2
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_UNSIGNED_LONG 4
#define SIZEOF_UNSIGNED_LONG_LONG 8
#define SIZEOF_INT_P 4

#define BX_64BIT_CONSTANTS_USE_LL 1
#if BX_64BIT_CONSTANTS_USE_LL
// doesn't work on Microsoft Visual C++, maybe others
#define BX_CONST64(x)  (x##LL)
#else
#define BX_CONST64(x)  (x)
#endif

#if defined(WIN32)
  typedef unsigned char      Bit8u;
  typedef   signed char      Bit8s;
  typedef unsigned short     Bit16u;
  typedef   signed short     Bit16s;
  typedef unsigned int       Bit32u;
  typedef   signed int       Bit32s;
#ifdef __MINGW32__
  typedef unsigned long long Bit64u;
  typedef   signed long long Bit64s;
#include <sys/types.h>
#else
  typedef unsigned __int64   Bit64u;
  typedef   signed __int64   Bit64s;
#endif
#elif BX_WITH_MACOS
  typedef unsigned char      Bit8u;
  typedef   signed char      Bit8s;
  typedef unsigned short     Bit16u;
  typedef   signed short     Bit16s;
  typedef unsigned int       Bit32u;
  typedef   signed int       Bit32s;
  typedef unsigned long long Bit64u;
  typedef   signed long long Bit64s;
#else

// Unix like platforms

#if SIZEOF_UNSIGNED_CHAR != 1
#  error "sizeof (unsigned char) != 1"
#else
  typedef unsigned char Bit8u;
  typedef   signed char Bit8s;
#endif

#if SIZEOF_UNSIGNED_SHORT != 2
#  error "sizeof (unsigned short) != 2"
#else
  typedef unsigned short Bit16u;
  typedef   signed short Bit16s;
#endif

#if SIZEOF_UNSIGNED_INT == 4
  typedef unsigned int Bit32u;
  typedef   signed int Bit32s;
#elif SIZEOF_UNSIGNED_LONG == 4
  typedef unsigned long Bit32u;
  typedef   signed long Bit32s;
#else
#  error "can't find sizeof(type) of 4 bytes!"
#endif

#if SIZEOF_UNSIGNED_LONG == 8
  typedef unsigned long Bit64u;
  typedef   signed long Bit64s;
#elif SIZEOF_UNSIGNED_LONG_LONG == 8
  typedef unsigned long long Bit64u;
  typedef   signed long long Bit64s;
#else
#  error "can't find data type of 8 bytes"
#endif

#endif

// now that Bit32u and Bit64u exist, defined bx_address
#if BX_SUPPORT_X86_64
typedef Bit64u bx_address;
#else
typedef Bit32u bx_address;
#endif


// technically, in an 8 bit signed the real minimum is -128, not -127.
// But if you decide to negate -128 you tend to get -128 again, so it's
// better not to use the absolute maximum in the signed range.
#define BX_MAX_BIT64U ( (Bit64u) -1           )
#define BX_MIN_BIT64U ( 0                     )
#define BX_MAX_BIT64S ( ((Bit64u) -1) >> 1    )
#define BX_MIN_BIT64S ( -(((Bit64u) -1) >> 1) )
#define BX_MAX_BIT32U ( (Bit32u) -1           )
#define BX_MIN_BIT32U ( 0                     )
#define BX_MAX_BIT32S ( ((Bit32u) -1) >> 1    )
#define BX_MIN_BIT32S ( -(((Bit32u) -1) >> 1) )
#define BX_MAX_BIT16U ( (Bit16u) -1           )
#define BX_MIN_BIT16U ( 0                     )
#define BX_MAX_BIT16S ( ((Bit16u) -1) >> 1    )
#define BX_MIN_BIT16S ( -(((Bit16u) -1) >> 1) )
#define BX_MAX_BIT8U  ( (Bit8u) -1            )
#define BX_MIN_BIT8U  ( 0                     )
#define BX_MAX_BIT8S  ( ((Bit8u) -1) >> 1     )
#define BX_MIN_BIT8S  ( -(((Bit8u) -1) >> 1)  )


// create an unsigned integer type that is the same size as a pointer.
// You can typecast a pointer to a bx_pr_equiv_t without losing any
// bits (and without getting the compiler excited).  This is used in
// the FPU emulation code, where pointers and integers are often
// used interchangeably.
#if SIZEOF_INT_P == 4
  typedef Bit32u bx_ptr_equiv_t;
#elif SIZEOF_INT_P == 8
  typedef Bit64u bx_ptr_equiv_t;
#else
#  error "could not define bx_ptr_equiv_t to size of int*"
#endif

// Use a boolean type that will not conflict with the builtin type
// on any system.
typedef Bit32u bx_bool;

#if BX_WITH_MACOS
#  define bx_ptr_t char *
#else
#  define bx_ptr_t void *
#endif

#if defined(WIN32)
#  define BX_LITTLE_ENDIAN
#elif BX_WITH_MACOS
#  define BX_BIG_ENDIAN
#else
#if WORDS_BIGENDIAN
#  define BX_BIG_ENDIAN
#else
#  define BX_LITTLE_ENDIAN
#endif
#endif // defined(WIN32)


#if BX_SUPPORT_X86_64
#ifdef BX_LITTLE_ENDIAN
typedef
  struct {
         Bit64u lo;
         Bit64u hi;
         } Bit128u;
typedef
  struct {
         Bit64u lo;
         Bit64s hi;
         } Bit128s;
#else   // must be Big Endian
typedef
  struct {
         Bit64u hi;
         Bit64u lo;
         } Bit128u;
typedef
  struct {
         Bit64s hi;
         Bit64u lo;
         } Bit128s;
#endif
#endif  // #if BX_SUPPORT_X86_64


// for now only term.cc requires a GUI sighandler.
#define BX_GUI_SIGHANDLER (BX_WITH_TERM)

#define HAVE_SIGACTION 1

// configure will change the definition of "inline" to the value
// that the C compiler allows.  It tests the following keywords to
// see if any is permitted: inline, __inline__, __inline.  If none
// is permitted, it defines inline to be empty.
#define inline inline

// inline functions in headers that are compiled with C compiler
// (e.g. fpu code) are declared with BX_C_INLINE macro.  Note that
// the word "inline" itself may now be redefined by the above #define.
// Many compilers are known to work with "static inline".  If the
// compiler can put the function inline, it does so and never creates
// a symbol for the function.  If optimization is off, or inline is
// defined to be empty, the static keyword causes the function to create
// a symbol that's visible only to that .c file.  Each .c file that
// includes the header will produde another local version of the
// BX_C_INLINE function (not ideal).  However without "static" you can
// duplicate symbol problems which are even worse.
#define BX_C_INLINE static inline

// Use BX_CPP_INLINE for all C++ inline functions.  Note that the
// word "inline" itself may now be redefined by the above #define.
#define BX_CPP_INLINE inline

#ifdef __GNUC__

// Some helpful compiler hints for compilers that allow them; GCC for now.
//
// BX_CPP_AlignN(n):
//   Align a construct on an n-byte boundary.
//
// BX_CPP_AttrPrintf(formatArg, firstArg):
//   This function takes printf-like arguments, so the compiler can check
//   the consistency of the format string and the matching arguments.
//   'formatArg' is the parameter number (starting from 1) of the format
//   string argument.  'firstArg' is the parameter number of the 1st argument
//   to check against the string argument.  NOTE: For non-static member
//   functions, the this-ptr is argument number 1 but is invisible on
//   the function prototype declaration - but you still have to count it.
//
// BX_CPP_AttrNoReturn():
//   This function never returns.  The compiler can optimize-out following
//   code accordingly.

#define BX_CPP_AlignN(n) __attribute__ ((aligned (n)))
#define BX_CPP_AttrPrintf(formatArg, firstArg) \
                          __attribute__ ((format (printf, formatArg, firstArg)))
#define BX_CPP_AttrNoReturn() __attribute__ ((noreturn))

#else

#define BX_CPP_AlignN(n) /* Not supported. */
#define BX_CPP_AttrPrintf(formatArg, firstArg)  /* Not supported. */
#define BX_CPP_AttrNoReturn() /* Not supported. */

#endif

#define BX_DEBUGGER 0
#define BX_DISASM 0

#define BX_PROVIDE_CPU_MEMORY 1
#define BX_PROVIDE_DEVICE_MODELS 1

#define BX_SUPPORT_VBE 0

#define BX_PROVIDE_MAIN       1

#define BX_INSTRUMENTATION 0

#define BX_USE_LOADER    0

// for debugger, CPU simulator handle ID
//   0 is the default, for using only one CPU simulator
//   1 is for the 2nd CPU simulator
#define BX_SIM_ID 0
#define BX_NUM_SIMULATORS 1

// limited i440FX PCI support
#define BX_PCI_SUPPORT 0

// Experimental VGA on PCI
#define BX_PCI_VGA_SUPPORT 1

// limited USB on PCI
#define BX_PCI_USB_SUPPORT 0

#if (BX_PCI_USB_SUPPORT && !BX_PCI_SUPPORT)
#error To enable USB, you must also enable PCI
#endif

// Promise VLBIDE DC2300 Support
#define BX_PDC20230C_VLBIDE_SUPPORT 0

#define BX_SUPPORT_FPU 1
#define BX_SUPPORT_MMX 1
#define BX_SUPPORT_3DNOW 0
#define BX_SUPPORT_SSE 0
#define BX_SUPPORT_DAZ 0
#define BX_SUPPORT_PNI 0
#define BX_SUPPORT_SEP 0
#define BX_SUPPORT_4MEG_PAGES 0

#define BX_SupportGuest2HostTLB 0
#define BX_SupportRepeatSpeedups 0
#define BX_SupportGlobalPages 0
#define BX_SupportPAE 0
#define BX_SupportICache 0
#define BX_SupportHostAsms 1


// if 1, don't do gpf on MSRs that we don't implement
#define BX_IGNORE_BAD_MSR 0

// ========================================================
// These are some very temporary hacks I made to the 64-bit
// support to help Peter with debugging etc.  They will be removed
// soon and there is no configure option for them (on purpose).
// By default, they are not compiled in.

// I set this to 1 to bail in instructions which may not be honoring
// the 64-bit widths of RIP/RSP.  If I trip a panic, then I clean
// the function up and remove the panic.  You don't have to use
// these.
#if 0
#define BailBigRSP(s) \
  if ( (RIP > 0xffffffff) || \
       (RSP > 0xffffffff) ) \
    BX_PANIC((s ": bailing due to big RSP value, mode==%u", \
              BX_CPU_THIS_PTR cpu_mode))
#else
#define BailBigRSP(s)
#endif
// ========================================================


#if (BX_SUPPORT_MMX && BX_CPU_LEVEL < 5)
#error With CPU level < 5, you must disable MMX support.
#endif

#if (!BX_SUPPORT_FPU && BX_CPU_LEVEL >= 5)
#error With CPU level >= 5, you must enable FPU support.
#endif

#if (BX_SUPPORT_MMX && !BX_SUPPORT_FPU)
#error "MMX cannot be compiled without FPU support"
#endif

#if (BX_SUPPORT_3DNOW && !BX_SUPPORT_MMX)
#error "3DNow! cannot be compiled without MMX support"
#endif

#if (BX_SUPPORT_SSE && !BX_SUPPORT_MMX)
#error "SSE cannot be compiled without FPU+MMX support"
#endif

#if (BX_CPU_LEVEL<6 && BX_SUPPORT_SSE)
#error SSE is only supported with CPU_LEVEL >= 6
#endif

#if (BX_SUPPORT_PNI && BX_SUPPORT_SSE <= 1)
#error "PNI cannot be compiled without SSE/SSE2 support"
#endif

#if (BX_CPU_LEVEL<6 && BX_SUPPORT_SEP)
#error SYSENTER/SYSEXIT only supported with CPU_LEVEL >= 6
#endif

#if BX_SUPPORT_X86_64
// Sanity checks to ensure that you cannot accidently use conflicting options.

#if BX_CPU_LEVEL < 5
#error X86-64 requires cpu level 6 or greater
#endif
#if (BX_SUPPORT_SSE<2)
#error X86-64 requires SSE2
#endif
#if !BX_SupportPAE
#error X86-64 requires Physical Address Extensions (PAE)
#endif
#if !BX_SupportGlobalPages
#error X86-64 requires Page Global Extension (PGE)
#endif
#if !BX_SUPPORT_4MEG_PAGES
#error X86-64 requires Page Size Extension (PSE)
#endif

#if BX_SUPPORT_SEP
#error SYSENTER/SYSEXIT not implemented for X86-64
#endif

#endif

#define BX_HAVE_GETENV 1
#define BX_HAVE_SETENV 1
#define BX_HAVE_SELECT 1
#define BX_HAVE_SNPRINTF 1
#define BX_HAVE_STRTOULL 1
#define BX_HAVE_STRTOUQ 1
#define BX_HAVE_STRDUP 1
#define BX_HAVE_STRREV 0
#define BX_HAVE_STRUCT_TIMEVAL 1

// used in term gui
#define BX_HAVE_COLOR_SET 0
#define BX_HAVE_MVHLINE 0
#define BX_HAVE_MVVLINE 0


// set if your compiler does not permit an empty struct
#define BX_NO_EMPTY_STRUCTS 0

// set if your compiler does not understand __attribute__ after a struct
#define BX_NO_ATTRIBUTES 0
#if BX_NO_ATTRIBUTES
#define GCC_ATTRIBUTE(x) /* attribute not supported */
#else
#define GCC_ATTRIBUTE __attribute__
#endif

// set to use fast function calls
#define BX_FAST_FUNC_CALL 0

// On gcc2.95+ x86 only
#if BX_FAST_FUNC_CALL && defined(__i386__) && defined(__GNUC__) && (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 95))
#  define BX_CPP_AttrRegparmN(X) __attribute__((regparm(X)))
#else
#  define BX_CPP_AttrRegparmN(X) /* Not defined */
#endif

// set if your compiler does not allow label at the end of a {} block
#define BX_NO_BLANK_LABELS 0

// set if you do have <hash_map>, used in bx_debug/dbg_main.c
#define BX_HAVE_HASH_MAP 0

// set if you do have <hash_map.h>, used in bx_debug/dbg_main.c
#define BX_HAVE_HASH_MAP_H 1

// set if you do have <set>, used in bx_debug/dbg_main.c
#define BX_HAVE_SET 1

// set if you do have <set.h>, used in bx_debug/dbg_main.c
#define BX_HAVE_SET_H 1

// Support x86 hardware debugger registers and facilites.
// These are the debug facilites offered by the x86 architecture,
// not the optional built-in debugger.
#define BX_X86_DEBUGGER 0

#define BX_SUPPORT_CDROM 1

#if BX_SUPPORT_CDROM
   // This is the C++ class name to use if we are supporting
   // low-level CDROM.
#  define LOWLEVEL_CDROM cdrom_interface
#endif

// NE2K network emulation
#define BX_NE2K_SUPPORT 0
#define BX_ETH_NULL_LOGGING 1
#define BX_ETH_FBSD_LOGGING 1

// determine which NE2K packet mover modules will be enabled
// (this was moved from iodev/eth.h)
#define ETH_NULL  1
#ifdef BX_USE_ETH_ARPBACK
#  define ETH_ARPBACK 1
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#define ETH_FBSD  1
#endif
#if defined(linux)
#define ETH_LINUX 1
#endif
#if defined(WIN32)
#define ETH_WIN32 1
#endif

// this enables Ethertap packet mover; determined by configure script
#define HAVE_ETHERTAP 0

// this enables TUN/TAP packet mover; determined by configure script
#define HAVE_TUNTAP 0


// I/O Interface to debug
#define BX_IODEBUG_SUPPORT 0

// External Debugger
#define BX_EXTERNAL_DEBUGGER 0
#define BX_OVERRIDE_ASK 0

#ifdef WIN32
#define BX_FLOPPY0_NAME "Floppy Disk A:"
#define BX_FLOPPY1_NAME "Floppy Disk B:"
#else
#define BX_FLOPPY0_NAME "Floppy Disk 0"
#define BX_FLOPPY1_NAME "Floppy Disk 1"
#endif

// This is handy for certain performance testing purposes, but otherwise
// totally useless.  If you define BX_SCHEDULED_DIE_TIME then it enables code
// in bx_pit_c::periodic that will cause Bochs to exit() after a certain number
// of instructions.
//#define BX_SCHEDULED_DIE_TIME 1162230000   // end of redhat6.0 boot


#endif  // _BX_CONFIG_H
