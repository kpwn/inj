//
//  libinject.c
//  inj
//
//  Created by qwertyoruiop on 31/07/15.
//  Copyright (c) 2015 kim jong cracks. All rights reserved.
//

#include "libinject.h"

void* libinj_map_mem(inject_t inj, size_t size, uint64_t* remote_map_virtaddr) {
    mach_vm_address_t local_vaddr=0;
    kern_return_t kr = mach_vm_allocate(mach_task_self_, &local_vaddr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS || !local_vaddr) {
        return 0;
    }
    mach_vm_protect(mach_task_self_, local_vaddr, size, 0, VM_PROT_READ|VM_PROT_WRITE);
    if (remote_map_virtaddr) {
        mach_port_t entry;
        memory_object_size_t pagesz = round_page(size);
        kr = mach_make_memory_entry_64(mach_task_self_, &pagesz, local_vaddr, VM_PROT_READ|VM_PROT_WRITE, &entry, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            puts("failed to make memory entry");
            mach_vm_deallocate(mach_task_self_, local_vaddr, size);
            return 0;
        }
        *remote_map_virtaddr = 0;
        
        kr = mach_vm_map(inj, remote_map_virtaddr, pagesz, 0, VM_FLAGS_ANYWHERE, entry, 0, 0, VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE, VM_INHERIT_NONE);
        if (kr) {
            printf("failed to map %s\n", mach_error_string(kr));
            *remote_map_virtaddr = 0;
            mach_vm_deallocate(mach_task_self_, local_vaddr, size);
            return 0;
        }
    }
    return (void*) local_vaddr;
}

inject_t libinj_inject_pid (pid_t pid)
{
    mach_port_t pt = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self_, pid, &pt);
    if (!pt || kr) {
        printf("task_for_pid error: %s\n", mach_error_string(kr));
        return 0;
    }
    return pt;
}

void* libinj_sym_findbin(inject_t task, void* addr, struct mach_header *mhi, const char *name);

vm_address_t libinj_mapsearch(inject_t inj, uint32_t filetype);


void* libinj_map_remote(inject_t inj, vm_address_t addr, mach_vm_size_t size) {
    void* mem = malloc(size);
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(inj, addr, size, (mach_vm_address_t)mem, (mach_vm_size_t*)&sz);
    if (kr != KERN_SUCCESS) {
        printf("[-] map failed (%p): %s\n", (void*)addr, mach_error_string(kr));
        free(mem);
        return 0;
    }
    return (void*) mem;
}

void libinj_free_map(inject_t inj, mach_vm_address_t addr, vm_size_t size) {
    free((void*)addr);
}

struct mach_header* libinj_map_mach_header(inject_t inj, vm_address_t addr) {
    struct mach_header* mh = libinj_map_remote(inj, addr, MAX(sizeof(struct mach_header), sizeof(struct mach_header_64)));
    if (mh->magic == MH_MAGIC) {
        struct mach_header* ret = libinj_map_remote(inj, addr, sizeof(struct mach_header) + mh->sizeofcmds);
        libinj_free_map(inj, (vm_address_t)mh, MAX(sizeof(struct mach_header), sizeof(struct mach_header_64)));
        return ret;
    } else if (mh->magic == MH_MAGIC_64) {
        struct mach_header_64* _mh = (struct mach_header_64*)mh;
        struct mach_header* ret = libinj_map_remote(inj, addr, sizeof(struct mach_header_64) + _mh->sizeofcmds);
        libinj_free_map(inj, (vm_address_t)mh, MAX(sizeof(struct mach_header), sizeof(struct mach_header_64)));
        return ret;
    }
    return 0;
}


struct mach_header* libinj_main_header(inject_t inj) {
    vm_address_t mh_add = libinj_mapsearch(inj, MH_EXECUTE);
    struct mach_header* mh = libinj_map_mach_header(inj, mh_add);
    return mh;
}

struct section_64 *find_section_64(struct segment_command_64 *seg, const char *name)
{
    struct section_64 *sect, *fs = NULL;
    uint32_t i = 0;
    for (i = 0, sect = (struct section_64 *)((uint64_t)seg + (uint64_t)sizeof(struct segment_command_64));
         i < seg->nsects;
         i++, sect = (struct section_64 *)((uint64_t)sect + sizeof(struct section_64)))
    {
        if (!strcmp(sect->sectname, name)) {
            fs = sect;
            break;
        }
    }
    return fs;
}

struct segment_command_64 *find_segment_64(struct mach_header_64 *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command_64 *s, *fs = NULL;
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT_64) {
            s = (struct segment_command_64 *)lc;
            if (!strcmp(s->segname, segname)) {
                fs = s;
                break;
            }
        }
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    return fs;
}

struct section *find_section(struct segment_command *seg, const char *name)
{
    struct section *sect, *fs = NULL;
    uint32_t i = 0;
    for (i = 0, sect = (struct section *)((uint64_t)seg + (uint64_t)sizeof(struct segment_command));
         i < seg->nsects;
         i++, sect = (struct section*)((uint64_t)sect + sizeof(struct section)))
    {
        if (!strcmp(sect->sectname, name)) {
            fs = sect;
            break;
        }
    }
    return fs;
}

struct segment_command *find_segment(struct mach_header *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command *s, *fs = NULL;
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT) {
            s = (struct segment_command *)lc;
            if (!strcmp(s->segname, segname)) {
                fs = s;
                break;
            }
        }
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    return fs;
}
struct dyld_image_info32 {
    uint32	imageLoadAddress;	/* base address image is mapped into */
    uint32					imageFilePath;		/* path dyld used to load the image */
    uint32					imageFileModDate;	/* time_t of image file */
};

void* libinj_find_symbol(inject_t inj, char* name) {
    //vm_address_t mh_add = libinj_mapsearch(inj, MH_EXECUTE);
    vm_address_t dy_add = libinj_mapsearch(inj, MH_DYLINKER);
    //struct mach_header* mh = libinj_map_mach_header(inj, mh_add);
    struct mach_header* dyld_mh = libinj_map_mach_header(inj, dy_add);
    struct dyld_all_image_infos* all_image_infos = NULL;
    void* all_img = (void*) libinj_sym_findbin(inj, (void*) dy_add, dyld_mh, "_dyld_all_image_infos");
    assert(all_img);
    all_image_infos = (struct dyld_all_image_infos*) libinj_map_remote(inj, (vm_address_t)all_img, sizeof(struct dyld_all_image_infos));
    assert(all_image_infos);
    struct dyld_image_info* info_table = (struct dyld_image_info*) libinj_map_remote(inj, (dyld_mh->magic == MH_MAGIC_64 ? (vm_address_t)all_image_infos->infoArray : (vm_address_t)(uint32_t)all_image_infos->infoArray), sizeof(struct dyld_image_info) * all_image_infos->infoArrayCount);
    assert(info_table);
    struct dyld_image_info32 *info_table_32 = (struct dyld_image_info32 *)info_table;
    for (int n=0; n < all_image_infos->infoArrayCount; n++) {
        vm_address_t lib_addr = 0;
        if (dyld_mh->magic == MH_MAGIC)
            lib_addr = (vm_address_t)info_table_32[n].imageLoadAddress;
        else if (dyld_mh->magic == MH_MAGIC_64)
            lib_addr = (vm_address_t)info_table[n].imageLoadAddress;
        struct mach_header* lib_header = libinj_map_mach_header(inj, lib_addr);
        void* sym = libinj_sym_findbin(inj, (void*)lib_addr, lib_header, name);
        if (sym) {
            printf("[+] found sym %s at %p\n", name, sym);
            libinj_free_map(inj, (vm_address_t)lib_header, 0);
            return sym;
        }
        libinj_free_map(inj, (vm_address_t)lib_header, 0);
    }
    return 0;
}

vm_address_t libinj_mapsearch(inject_t inj, uint32_t filetype) {
    kern_return_t kr      = KERN_SUCCESS;
    vm_address_t  address = 0;
    vm_size_t     size    = 0;
    
    while (1) {
        mach_msg_type_number_t count;
        struct vm_region_submap_info_64 info;
        uint32_t nesting_depth;
        
        count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kr = vm_region_recurse_64(inj, &address, &size, &nesting_depth,
                                  (vm_region_info_64_t)&info, &count);
        if (kr == KERN_INVALID_ADDRESS) {
            break;
        } else if (kr) {
            mach_error("vm_region:", kr);
            break; /* last region done */
        }
        
        if (info.is_submap) {
            nesting_depth++;
        } else {
            char* bin = malloc(sizeof(struct mach_header));
            mach_vm_size_t sz = 0;
            //printf("region: %p -> %p (%lx bytes) - prot: %s%s%s\n", (void*)address, (void*)(address+size), size, info.protection&PROT_READ ? "r" : "-",info.protection&PROT_WRITE ? "w" : "-",info.protection&PROT_EXEC ? "x" : "-" );
            
            if (info.protection & PROT_EXEC) {
                if(mach_vm_read_overwrite(inj, address, sizeof(struct mach_header), (mach_vm_address_t)bin, (mach_vm_size_t*)&sz)) {
                    //puts("error reading");
                } else {
                    if (*(uint32_t*) bin == MH_MAGIC) {
                        struct mach_header* hd = (struct mach_header*)bin;
                        if (hd->filetype == filetype) {
                            free(bin);
                            return (vm_address_t)address;
                        }
                    } else if(*(uint32_t*) bin == MH_MAGIC_64) {
                        struct mach_header_64* hd = (struct mach_header_64*)bin;
                        if (hd->filetype == filetype) {
                            free(bin);
                            return (vm_address_t)address;
                        }
                    }
                }
            }
            free(bin);
            address += size;
        }
    }
    return 0;
}

struct load_command *find_load_command_64(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *flc;
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            flc = (struct load_command *)lc;
            break;
        }
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    return flc;
}
struct load_command *find_load_command(struct mach_header *mh, uint32_t cmd)
{
    struct load_command *lc, *flc;
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            flc = (struct load_command *)lc;
            break;
        }
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    return flc;
}

uint64_t get_vmaddr_slide(struct mach_header *mh, void* addr) {
    uint64_t vmaddr_slide = -1;
    
    if (mh->magic == MH_MAGIC_64) {
        struct mach_header_64* mhi = (struct mach_header_64*) mh;
        struct load_command *loadCmd = (struct load_command*) (mhi + 1);
        
        for (uint32_t i=0; i < mhi->ncmds; i++) {
            if (loadCmd->cmd == LC_SEGMENT) {
                struct segment_command* segment = (struct segment_command*)loadCmd;
                if (segment->fileoff == 0) { // header + load commmand segment
                    vmaddr_slide = (uint64_t) addr - segment->vmaddr;
                    break;
                }
            }
            else if (loadCmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64* segment64 = (struct segment_command_64*)loadCmd;
                if (segment64->fileoff == 0) { // header + load commmand segment
                    vmaddr_slide = (uint64_t) addr - segment64->vmaddr;
                    break;
                }
            }
        }
    } else if (mh->magic == MH_MAGIC) {
        struct mach_header* mhi = (struct mach_header*) mh;
        struct load_command *loadCmd = (struct load_command*) (mhi + 1);
        
        for (uint32_t i=0; i < mhi->ncmds; i++) {
            if (loadCmd->cmd == LC_SEGMENT) {
                struct segment_command* segment = (struct segment_command*)loadCmd;
                if (segment->fileoff == 0) { // header + load commmand segment
                    vmaddr_slide = (uint64_t) addr - segment->vmaddr;
                    break;
                }
            }
            else if (loadCmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64* segment64 = (struct segment_command_64*)loadCmd;
                if (segment64->fileoff == 0) { // header + load commmand segment
                    vmaddr_slide = (uint64_t) addr - segment64->vmaddr;
                    break;
                }
            }
        }
    }
    return vmaddr_slide;
}

void* libinj_sym_findbin(inject_t task, void* addr, struct mach_header *mhi, const char *name) {
    if (mhi->magic == MH_MAGIC_64) {
        struct mach_header_64* mh = (struct mach_header_64*)mhi;
        struct segment_command_64 *linkedit = find_segment_64(mh, SEG_LINKEDIT);
        struct symtab_command *symtab = (struct symtab_command *)find_load_command_64(mh, LC_SYMTAB);
        assert (linkedit);
        assert (symtab);

        uint64_t vmaddr_slide = get_vmaddr_slide(mhi, addr);
        char* sym_str_table = libinj_map_remote(task, linkedit->vmaddr + vmaddr_slide + symtab->stroff - linkedit->fileoff, symtab->strsize);
        
        if(!sym_str_table) return 0;
        
        struct nlist_64* sym_table = (struct nlist_64*) libinj_map_remote(task, linkedit->vmaddr + vmaddr_slide + symtab->symoff - linkedit->fileoff, symtab->nsyms * sizeof(struct nlist_64));
        
        void* ret_value = 0;
        
        for (int i = 0; i < symtab->nsyms; i++) {
            if (sym_table[i].n_value && !strcmp(name,&sym_str_table[sym_table[i].n_un.n_strx])) {
                ret_value = (void*) (uint64_t) (sym_table[i].n_value + vmaddr_slide);
                break;
            }
        }
        
        libinj_free_map(task, (vm_address_t)sym_table, 0);
        libinj_free_map(task, (vm_address_t)sym_str_table, 0);
        return ret_value;
    } else if(mhi->magic == MH_MAGIC) {
        struct mach_header* mh = (struct mach_header*)mhi;
        struct segment_command *linkedit = find_segment(mh, SEG_LINKEDIT);
        struct symtab_command *symtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
        assert (linkedit);
        assert (symtab);
        
        uint64_t vmaddr_slide = get_vmaddr_slide(mhi, addr);
        char* sym_str_table = libinj_map_remote(task, linkedit->vmaddr + vmaddr_slide + symtab->stroff - linkedit->fileoff, symtab->strsize);
        
        assert(sym_str_table);
        
        struct nlist* sym_table = (struct nlist*) libinj_map_remote(task, linkedit->vmaddr + vmaddr_slide + symtab->symoff - linkedit->fileoff, symtab->nsyms * sizeof(struct nlist));
        
        void* ret_value = 0;
        
        for (int i = 0; i < symtab->nsyms; i++) {
            if (sym_table[i].n_value && !strcmp(name,&sym_str_table[sym_table[i].n_un.n_strx])) {
                ret_value = (void*) (uint64_t) (sym_table[i].n_value + vmaddr_slide);
                break;
            }
        }
        
        libinj_free_map(task, (vm_address_t)sym_table, 0);
        libinj_free_map(task, (vm_address_t)sym_str_table, 0);
        return ret_value;
    }
    return 0;
}
mach_port_t libinj_create_thread (inject_t inj, unsigned long* stack, void* initial_instr) {
    struct mach_header* x = libinj_main_header(inj);
    if (x->magic == MH_MAGIC) {
        // 32 bit
        i386_thread_state_t state;
        bzero(&state,sizeof(state));
        state.__eip = (uint32_t)initial_instr;
        state.__esp = (uint32_t)stack;
        thread_act_t th;
        if(KERN_SUCCESS == thread_create_running(inj, i386_THREAD_STATE, (thread_state_t)&state, i386_THREAD_STATE_COUNT, &th)) {
            free(x);
            return th;
        }
    } else if (x->magic == MH_MAGIC_64) {
        // 64 bit
        x86_thread_state64_t state;
        bzero(&state,sizeof(state));
        state.__rip = (uint64_t)initial_instr;
        state.__rsp = (uint64_t)stack;
        thread_act_t th;
        if(KERN_SUCCESS == thread_create_running(inj, x86_THREAD_STATE64,(thread_state_t) &state, x86_THREAD_STATE64_COUNT, &th)) {
            free(x);
            return th;
        }
    }
    free(x);
    return 0;
}
void* libinj_copyout(inject_t inj, void* data, size_t size) {
    vm_size_t sz = round_page(size);
    uint64_t ptr=0;
    kern_return_t kr = mach_vm_allocate(inj, &ptr, sz, 1);
    if(kr != KERN_SUCCESS) {
        puts("vm_allocate fail");
        return (void*)ptr;
    }
    if(mach_vm_write(inj, ptr, (vm_offset_t)data, (mach_msg_type_number_t)size) == KERN_SUCCESS) return (void*)ptr;
    mach_vm_deallocate(inj, (mach_vm_address_t)data, size);
    return 0;
}



