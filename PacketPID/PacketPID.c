/*
 * original KernelResolver.c
 * by snare (snare@ho.ax)
 *
 * Mountain Lion port
 * by @_rc0r
 *
 *
 *
 * This is a simple example of how to resolve symbols in the kernel from within
 * a kernel extension. Symbols can be solved by using the kernel image from disk
 * (find_symbol_from_disk) and from memory (find_symbol).
 *
 * See the following URLs for more info:
 * http://ho.ax/posts/2012/02/resolving-kernel-symbols/
 * and
 * http://reverse.put.as/2013/05/08/there-is-an-error-in-my-syscan-slides/
 *
 */

#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <sys/fcntl.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>

#ifdef DEBUG
#define DLOG(args...)   printf(args)
#elif
#define DLOG(args...)   /* */
#endif

struct descriptor_idt
{
    uint16_t offset_low;
    uint16_t seg_selector;
    uint8_t reserved;
    uint8_t flag;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved2;
};

/* Borrowed from kernel source. It doesn't exist in Kernel.framework. */
struct nlist_64 {
    union {
        uint32_t  n_strx;   /* index into the string table */
    } n_un;
    uint8_t n_type;         /* type flag, see below */
    uint8_t n_sect;         /* section number or NO_SECT */
    uint16_t n_desc;        /* see <mach-o/stab.h> */
    uint64_t n_value;       /* value of this symbol (or stab offset) */
};


kern_return_t KernelResolver_start(kmod_info_t * ki, void *d);
kern_return_t KernelResolver_stop(kmod_info_t *ki, void *d);
struct segment_command_64 *find_segment_64(struct mach_header_64 *mh, const char *segname);
struct section_64 *find_section_64(struct segment_command_64 *seg, const char *name);
struct load_command *find_load_command(struct mach_header_64 *mh, uint32_t cmd);
void *find_symbol(struct mach_header_64 *mh, const char *name);
void *find_symbol_from_disk( vm_address_t slide, const char *name );
uint64_t find_kernel_baseaddr( void );

uint64_t KERNEL_MH_START_ADDR;

kern_return_t KernelResolver_start(kmod_info_t * ki, void *d)
{
    if( find_kernel_baseaddr() != 0 )
    {
        DLOG( "[+] Can't find KERNEL_MH_START_ADDR!\n" );
        return KERN_FAILURE;
    }
    
    void *fkmod, *mkmod;
    
    DLOG("[+] _allproc @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "_allproc"));
    DLOG("[+] _proc_lock @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "_proc_lock"));
    DLOG("[+] _kauth_cred_setuidgid @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "_kauth_cred_setuidgid"));
    DLOG("[+] __ZN6OSKext13loadFromMkextEjPcjPS0_Pj @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "__ZN6OSKext13loadFromMkextEjPcjPS0_Pj"));
    DLOG("[+] _nsysent @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "_nsysent"));
    mkmod = find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR, "_kmod");
    DLOG("[+] _kmod from mem. @ %p\n", mkmod );
    fkmod = find_symbol_from_disk( 0,  "_kmod" );
    DLOG( "[+] _kmod from file @ %p\n", fkmod );
    DLOG( "[+] KASLR slide: %016lx\n", mkmod - fkmod );
    
    return KERN_SUCCESS;
}

kern_return_t KernelResolver_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}

struct segment_command_64 *
find_segment_64(struct mach_header_64 *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command_64 *seg, *foundseg = NULL;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT_64) {
            /* Check load command's segment name */
            seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, segname) == 0) {
                foundseg = seg;
                break;
            }
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the segment (NULL if we didn't find it) */
    return foundseg;
}

struct section_64 *
find_section_64(struct segment_command_64 *seg, const char *name)
{
    struct section_64 *sect, *foundsect = NULL;
    u_int i = 0;
    
    /* First section begins straight after the segment header */
    for (i = 0, sect = (struct section_64 *)((uint64_t)seg + (uint64_t)sizeof(struct segment_command_64));
         i < seg->nsects;
         i++, sect = (struct section_64 *)((uint64_t)sect + sizeof(struct section_64)))
    {
        /* Check section name */
        if (strcmp(sect->sectname, name) == 0) {
            foundsect = sect;
            break;
        }
    }
    
    /* Return the section (NULL if we didn't find it) */
    return foundsect;
}

struct load_command *
find_load_command(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *foundlc;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            foundlc = (struct load_command *)lc;
            break;
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the load command (NULL if we didn't find it) */
    return foundlc;
}

void *
find_symbol(struct mach_header_64 *mh, const char *name)
{
    struct symtab_command *msymtab = NULL;
    struct segment_command_64 *mlc = NULL;
    struct segment_command_64 *mlinkedit = NULL;
    void *mstrtab = NULL;
    
    struct nlist_64 *nl = NULL;
    char *str;
    uint64_t i;
    void *addr = NULL;
    
    /*
     * Check header
     */
    if (mh->magic != MH_MAGIC_64) {
        DLOG("FAIL: magic number doesn't match - 0x%x\n", mh->magic);
        return NULL;
    }
    
    /*
     * Find TEXT section
     */
    mlc = find_segment_64(mh, SEG_TEXT);
    if (!mlc) {
        DLOG("FAIL: couldn't find __TEXT\n");
        return NULL;
    }
    
    /*
     * Find the LINKEDIT and SYMTAB sections
     */
    mlinkedit = find_segment_64(mh, SEG_LINKEDIT);
    if (!mlinkedit) {
        DLOG("FAIL: couldn't find __LINKEDIT\n");
        return NULL;
    }
    
    msymtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
    if (!msymtab) {
        DLOG("FAIL: couldn't find SYMTAB\n");
        return NULL;
    }
    
    //DLOG( "[+] __TEXT.vmaddr      0x%016llX\n", mlc->vmaddr );
    //DLOG( "[+] __LINKEDIT.vmaddr  0x%016llX\n", mlinkedit->vmaddr );
    //DLOG( "[+] __LINKEDIT.vmsize  0x%08llX\n", mlinkedit->vmsize );
    //DLOG( "[+] __LINKEDIT.fileoff 0x%08llX\n", mlinkedit->fileoff );
    //DLOG( "[+] LC_SYMTAB.stroff   0x%08X\n", msymtab->stroff );
    //DLOG( "[+] LC_SYMTAB.strsize  0x%08X\n", msymtab->strsize );
    //DLOG( "[+] LC_SYMTAB.symoff   0x%08X\n", msymtab->symoff );
    //DLOG( "[+] LC_SYMTAB.nsyms    0x%08X\n", msymtab->nsyms );
    
    /*
     * Enumerate symbols until we find the one we're after
     *
     *  Be sure to use NEW calculation STRTAB in Mountain Lion!
     */
    mstrtab = (void *)((int64_t)mlinkedit->vmaddr + (msymtab->stroff - mlinkedit->fileoff));
    
    // First nlist_64 struct is NOW located @:
    for (i = 0, nl = (struct nlist_64 *)(mlinkedit->vmaddr + (msymtab->symoff - mlinkedit->fileoff));
         i < msymtab->nsyms;
         i++, nl = (struct nlist_64 *)((uint64_t)nl + sizeof(struct nlist_64)))
    {
        str = (char *)mstrtab + nl->n_un.n_strx;
        
        if (strcmp(str, name) == 0) {
            addr = (void *)nl->n_value;
        }
    }
    
    /* Return the address (NULL if we didn't find it) */
    return addr;
}

void *
find_symbol_from_disk( vm_offset_t slide, const char *name )
{
    struct symtab_command *fsymtab = NULL;
    struct segment_command_64 *flc = NULL;
    struct segment_command_64 *flinkedit = NULL;
    void *fstrtab = NULL;
    
    struct nlist_64 *nl = NULL;
    char *str;
    uint64_t i;
    void *addr = NULL;
    
#define MY_BSIZE    1024*1000   // ~1 MByte
    
    vnode_t kernel_node = NULL;
    vfs_context_t ctx = NULL;
    
    int error;
    
    // Buffer creation
    char header_buffer[ PAGE_SIZE_64 ];
    uio_t uio = NULL;
    
    uio = uio_create( 1, 0, UIO_SYSSPACE, UIO_READ );
    
    if( ( error = uio_addiov( uio, CAST_USER_ADDR_T( header_buffer ), PAGE_SIZE_64 ) ) )
    {
        DLOG( "[+] FAIL: uio_addiov\n" );
        return NULL;
    }
    
    // VFS access
    if( ( error = vnode_lookup( "/mach_kernel", 0, &kernel_node, NULL ) ) != 0 )
    {
        DLOG( "[+] FAIL: vnode_lookup\n" );
        return NULL;
    }
    
    ctx = vfs_context_current();
    
    if( ( error = vnode_open( "/mach_kernel", O_RDONLY, 0, 0, &kernel_node, ctx ) ) )
    {
        DLOG( "[+] FAIL: vnode_open\n" );
        return NULL;
    }
    
    if( ( error = VNOP_READ( kernel_node, uio, 0, ctx) ) )
    {
        DLOG( "[+] FAIL: VNOP_READ\n" );
        return NULL;
    }
    
    struct mach_header_64 *mmh = (struct mach_header_64 *)((void *)header_buffer);
    
    /*
     *  Check header
     */
    if( mmh->magic != MH_MAGIC_64 ) {
        DLOG("FAIL: magic number doesn't match - 0x%x\n", mmh->magic);
        return NULL;
    }
    
    flc = find_segment_64(mmh, SEG_TEXT);
    if (!flc) {
        DLOG("FAIL: couldn't find __TEXT\n");
        return NULL;
    }
    
    flinkedit = find_segment_64(mmh, SEG_LINKEDIT);
    if (!flinkedit) {
        DLOG("FAIL: couldn't find __LINKEDIT\n");
        return NULL;
    }
    
    fsymtab = (struct symtab_command *)find_load_command(mmh, LC_SYMTAB);
    if (!fsymtab) {
        DLOG("FAIL: couldn't find SYMTAB\n");
        return NULL;
    }
    
    //    DLOG( "[+] f:__TEXT.vmaddr      0x%016llX\n", flc->vmaddr );
    //    DLOG( "[+] f:__LINKEDIT.vmaddr  0x%016llX\n", flinkedit->vmaddr );
    //    DLOG( "[+] f:__LINKEDIT.vmsize  0x%08llX\n", flinkedit->vmsize );
    //    DLOG( "[+] f:__LINKEDIT.fileoff 0x%08llX\n", flinkedit->fileoff );
    //    DLOG( "[+] f:LC_SYMTAB.stroff   0x%08X\n", fsymtab->stroff );
    //    DLOG( "[+] f:LC_SYMTAB.strsize  0x%08X\n", fsymtab->strsize );
    //    DLOG( "[+] f:LC_SYMTAB.symoff   0x%08X\n", fsymtab->symoff );
    //    DLOG( "[+] f:LC_SYMTAB.nsyms    0x%08X\n", fsymtab->nsyms );
    
    // !!!
    // uio free()
    uio_free( uio );
    
    // read LINKEDIT section from file
    void *sec_buffer = _MALLOC( MY_BSIZE, M_TEMP, (M_ZERO|M_WAITOK) );
    
    if( sec_buffer == NULL )
    {
        DLOG( "[+] _MALLOC failed!\n" );
        return NULL;
    }
    
    uio_t uio2 = NULL;
    off_t off = flinkedit->fileoff;
    
    uio2 = uio_create( 1, off, UIO_SYSSPACE, UIO_READ );
    
    if( ( error = uio_addiov( uio2, CAST_USER_ADDR_T( sec_buffer ), MY_BSIZE ) ) )
    {
        DLOG( "[+] FAIL: uio_addiov\n" );
        return NULL;
    }
    
    if( ( error = VNOP_READ( kernel_node, uio2, 0, ctx) ) )
    {
        DLOG( "[+] FAIL: VNOP_READ (%d)\n", error );
        return NULL;
    }
    
    /*
     * Enumerate symbols until we find the one we're after
     */
    fstrtab = (void *)((int64_t)sec_buffer + (fsymtab->stroff - flinkedit->fileoff));
    
    for (i = 0, nl = (struct nlist_64 *)(sec_buffer + (fsymtab->symoff - flinkedit->fileoff));
         i < fsymtab->nsyms;
         i++, nl = (struct nlist_64 *)((uint64_t)nl + sizeof(struct nlist_64)))
    {
        str = (char *)fstrtab + nl->n_un.n_strx;
        
        if (strcmp(str, name) == 0) {
            addr = (void *)nl->n_value;
        }
    }
    
    _FREE( sec_buffer, M_TEMP );
    uio_free( uio2 );
    
    vnode_close( kernel_node, FREAD, ctx );
    
    /* Return the address (NULL if we didn't find it) */
    if( addr == NULL )
        return NULL;
    else
        return (addr + slide);
}

uint64_t find_kernel_baseaddr( )
{
    uint8_t idtr[ 10 ];
    uint64_t idt = 0;
    
    __asm__ volatile ( "sidt %0": "=m" ( idtr ) );
    
    idt = *( ( uint64_t * ) &idtr[ 2 ] );
    struct descriptor_idt *int80_descriptor = NULL;
    uint64_t int80_address = 0;
    uint64_t high = 0;
    uint32_t middle = 0;
    
    int80_descriptor = _MALLOC( sizeof( struct descriptor_idt ), M_TEMP, M_WAITOK );
    bcopy( (void*)idt, int80_descriptor, sizeof( struct descriptor_idt ) );
    
    high = ( unsigned long ) int80_descriptor->offset_high << 32;
    middle = ( unsigned int ) int80_descriptor->offset_middle << 16;
    int80_address = ( uint64_t )( high + middle + int80_descriptor->offset_low );
    
    uint64_t temp_address = int80_address;
    uint8_t *temp_buffer = _MALLOC( 4, M_TEMP, M_WAITOK );
    
    while( temp_address > 0 )
    {
        bcopy( ( void * ) temp_address, temp_buffer, 4 );
        if ( *( uint32_t * )( temp_buffer ) == MH_MAGIC_64 )
        {
            KERNEL_MH_START_ADDR = temp_address;
            return 0;
        }
        temp_address -= 1;
    }
    
    return -1;
}
