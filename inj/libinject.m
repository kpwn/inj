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

void* map_segment(inject_t task, uint64_t hint_addr, char* segname, void* task_addr, struct mach_header* header, uint64_t* fileoff, uint64_t* vmaddr_slide_){
    if (header->magic == MH_MAGIC_64) {
        struct mach_header_64* mhi = (struct mach_header_64*) header;
        struct load_command *loadCmd = (struct load_command*) (mhi + 1);
        
        uint64_t vmaddr_slide = 0;
        
        for (uint32_t i=0; i < mhi->ncmds; i++) {
            if (loadCmd->cmd == LC_SEGMENT) {
                struct segment_command* segment = (struct segment_command*)loadCmd;
                if (segment->fileoff == 0) { // header + load commmand segment
                    vmaddr_slide = (uint64_t) task_addr - segment->vmaddr;
                    break;
                }
            }
            else if (loadCmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64* segment64 = (struct segment_command_64*)loadCmd;
                if (segment64->fileoff == 0) { // header + load commmand segment
                    vmaddr_slide = (uint64_t) task_addr - segment64->vmaddr;
                    break;
                }
            }
        }
        
        for (uint32_t i=0; i < mhi->ncmds; i++) {
            if (loadCmd->cmd == LC_SEGMENT) {
                struct segment_command* segment = (struct segment_command*)loadCmd;
                if ((hint_addr == -1 || (segment->vmaddr < (uint32_t) hint_addr && segment->vmaddr + segment->vmsize
                                         > (uint32_t)hint_addr)) && (!segname || strcmp(segment->segname, segname) == 0)) {
                    char* ret = malloc(segment->vmsize);
                    mach_vm_size_t osz = segment->vmsize;
                    kern_return_t kr = mach_vm_read_overwrite(task, segment->vmaddr + vmaddr_slide, segment->vmsize, (mach_vm_address_t) ret, &osz);
                    if (osz != segment->vmsize || kr) {
                        printf("[-] failed to map a segment, skipping 0x%x - %x bytes (%s)\n", segment->vmaddr, segment->vmsize, segment->segname);
                        return NULL;
                    }
                    *fileoff = segment->fileoff;
                    *vmaddr_slide_ = vmaddr_slide;
                    return ret;
                }
            } else if (loadCmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64* segment64 = (struct segment_command_64*)loadCmd;
                if ((hint_addr == -1 || (segment64->vmaddr < (uint64_t) hint_addr && segment64->vmaddr + segment64->vmsize
                                          > hint_addr)) && (!segname || strcmp(segment64->segname, segname) == 0)) {
                    char* ret = malloc(segment64->vmsize);
                    mach_vm_size_t osz = segment64->vmsize;
                    kern_return_t kr = mach_vm_read_overwrite(task, segment64->vmaddr + vmaddr_slide, segment64->vmsize, (mach_vm_address_t) ret, &osz);
                    //printf("LC_COMMAND64 at %p with %llu size\n", (void*)segment64->vmaddr+ vmaddr_slide, segment64->vmsize);
                    if (osz != segment64->vmsize || kr) {
                        printf("[-] failed to map a segment, skipping 0x%llx - %llx bytes (%s)\n", segment64->vmaddr, segment64->vmsize, segment64->segname);
                        return NULL;
                    }
                    *fileoff = segment64->fileoff;
                    *vmaddr_slide_ = vmaddr_slide;
                    return ret;
                }
            }
            loadCmd = (struct load_command* ) (((char*)loadCmd) + loadCmd->cmdsize);
            if ((char*)loadCmd > (mhi->sizeofcmds + (char*)mhi)) {
                printf("inconsistent sizeofcmds / ncmds\n");
                break;
            }
        }
    } else if (header->magic == MH_MAGIC) {
        struct mach_header* mhi = (struct mach_header*) header;
        struct load_command *loadCmd = (struct load_command*) (mhi + 1);
        
        uint64_t vmaddr_slide = 0;
        
        for (uint32_t i=0; i < mhi->ncmds; i++) {
            if (loadCmd->cmd == LC_SEGMENT) {
                struct segment_command* segment = (struct segment_command*)loadCmd;
                if (segment->fileoff == 0) { // header + load commmand segment
                    vmaddr_slide = (uint64_t) task_addr - segment->vmaddr;
                    break;
                }
            }
            else if (loadCmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64* segment64 = (struct segment_command_64*)loadCmd;
                if (segment64->fileoff == 0) { // header + load commmand segment
                    vmaddr_slide = (uint64_t) task_addr - segment64->vmaddr;
                    break;
                }
            }
        }
        
        for (uint32_t i=0; i < mhi->ncmds; i++) {
            if (loadCmd->cmd == LC_SEGMENT) {
                struct segment_command* segment = (struct segment_command*)loadCmd;
                if ((hint_addr == -1 || (segment->vmaddr < (uint32_t) hint_addr && segment->vmaddr + segment->vmsize
                                         > (uint32_t)hint_addr)) && (!segname || strcmp(segment->segname, segname) == 0)) {
                    char* ret = malloc(segment->vmsize);
                    mach_vm_size_t osz = segment->vmsize;
                    kern_return_t kr = mach_vm_read_overwrite(task, segment->vmaddr + vmaddr_slide, segment->vmsize, (mach_vm_address_t) ret, &osz);
                    if (osz != segment->vmsize || kr) {
                        printf("[-] failed to map a segment, skipping 0x%x - %x bytes (%s)\n", segment->vmaddr, segment->vmsize, segment->segname);
                        return NULL;
                    }
                    *fileoff = segment->fileoff;
                    *vmaddr_slide_ = vmaddr_slide;
                    return ret;
                }
            } else if (loadCmd->cmd == LC_SEGMENT_64) {
                struct segment_command_64* segment64 = (struct segment_command_64*)loadCmd;
                if ((hint_addr == -1 || (segment64->vmaddr < (uint64_t) hint_addr && segment64->vmaddr + segment64->vmsize
                                         > hint_addr)) && (!segname || strcmp(segment64->segname, segname) == 0)) {
                    char* ret = malloc(segment64->vmsize);
                    mach_vm_size_t osz = segment64->vmsize;
                    kern_return_t kr = mach_vm_read_overwrite(task, segment64->vmaddr + vmaddr_slide, segment64->vmsize, (mach_vm_address_t) ret, &osz);
                    //printf("LC_COMMAND64 at %p with %llu size\n", (void*)segment64->vmaddr+ vmaddr_slide, segment64->vmsize);
                    if (osz != segment64->vmsize || kr) {
                        printf("[-] failed to map a segment, skipping 0x%llx - %llx bytes (%s)\n", segment64->vmaddr, segment64->vmsize, segment64->segname);
                        return NULL;
                    }
                    *fileoff = segment64->fileoff;
                    *vmaddr_slide_ = vmaddr_slide;
                    return ret;
                }
            }
            loadCmd = (struct load_command* ) (((char*)loadCmd) + loadCmd->cmdsize);
            if ((char*)loadCmd > (mhi->sizeofcmds + (char*)mhi)) {
                printf("inconsistent sizeofcmds / ncmds\n");
                break;
            }
        }
    }
    return 0;
}

struct mach_header* libinj_main_header(inject_t inj) {
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
            char* bin = malloc(size);
            mach_vm_size_t sz = 0;
            //printf("region: %p -> %p (%lx bytes) - prot: %s%s%s\n", (void*)address, (void*)(address+size), size, info.protection&PROT_READ ? "r" : "-",info.protection&PROT_WRITE ? "w" : "-",info.protection&PROT_EXEC ? "x" : "-" );
            
            if (info.protection&PROT_EXEC) {
                if(mach_vm_read_overwrite(inj, address, size, (mach_vm_address_t)bin, (mach_vm_size_t*)&sz)) {
                    puts("error reading");
                } else {
                    if (*(uint32_t*) bin == MH_MAGIC || *(uint32_t*) bin == MH_MAGIC_64) {
                        struct mach_header* hd = (struct mach_header*)bin;
                        if (hd->filetype == MH_EXECUTE) {
                            return hd;
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
void* libinj_find_symbol(inject_t inj, char* name) {
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
            char* bin = malloc(size);
            mach_vm_size_t sz = 0;
            //printf("region: %x/%p -> %p (%lx bytes) - prot: %s%s%s\n", (void*)address, (void*)address, (void*)(address+size), size, info.protection&PROT_READ ? "r" : "-",info.protection&PROT_WRITE ? "w" : "-",info.protection&PROT_EXEC ? "x" : "-" );

            if (info.protection&PROT_EXEC) {
                    if(mach_vm_read_overwrite(inj, address, size, (mach_vm_address_t)bin, (mach_vm_size_t*)&sz)) {
                        puts("error reading");
                    } else {
                        if (*(uint32_t*) bin == MH_MAGIC) {
                            struct mach_header* hd = (struct mach_header*)bin;
                            if (hd->filetype == MH_EXECUTE) {
                                //puts("main binary 32");
                            } else if (hd->filetype == MH_DYLINKER) {
                               // puts("dyld 32");
                                uint64_t dyld_img_info = libinj_sym_findbin(inj, address, (struct mach_header*)hd, "_dyld_all_image_infos");
                                if (!dyld_img_info) {
                                    puts("couldn't find dyld info");
                                    return 0;
                                }
                                uint64_t fileoff=0, vmaddr_slide=0;
                                
                                void* data = map_segment(inj, -1, "__DATA", (void*)address, (struct mach_header*)hd, &fileoff, &vmaddr_slide);
                                
                                if (!data) {
                                    puts("couldn't map data");
                                    return NULL;
                                }
                                struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)( (char*)data + dyld_img_info - fileoff - address);
                                struct dyld_image_info32 {
                                    uint32	imageLoadAddress;	/* base address image is mapped into */
                                    uint32					imageFilePath;		/* path dyld used to load the image */
                                    uint32					imageFileModDate;	/* time_t of image file */
                                    /* if stat().st_mtime of imageFilePath does not match imageFileModDate, */
                                    /* then file has been modified since dyld loaded it */
                                };

                                struct dyld_image_info32* imginfo = (struct dyld_image_info* )((char*)data + (uint32_t)infos->infoArray - fileoff - address);
                                
                                for (int n=0; n < infos->infoArrayCount; n++) {
                                    //printf("=> binary found: %x\n",imginfo[n].imageLoadAddress);
                                    mach_vm_size_t sz=0;
                                    struct mach_header hdr;
                                    mach_vm_read_overwrite(inj, (uint32_t)imginfo[n].imageLoadAddress, sizeof(struct mach_header), &hdr, &sz);
                                    if (sz != sizeof(struct mach_header)) {
                                        puts("couldn't read");
                                        return NULL;
                                    } else {
                                        if (hdr.magic == MH_MAGIC_64) {
                                            struct mach_header_64 hdr;
                                            mach_vm_read_overwrite(inj, (uint32_t)imginfo[n].imageLoadAddress, sizeof(struct mach_header_64), &hdr, &sz);
                                            if (sz != sizeof(struct mach_header_64)) {
                                                puts("couldn't read");
                                                return NULL;
                                            }
                                            sz += hdr.sizeofcmds;
                                            char* lc = malloc(sz);
                                            mach_vm_size_t rsz = sz;
                                            mach_vm_read_overwrite(inj, (uint32_t)imginfo[n].imageLoadAddress, sz, lc, &rsz);
                                            if (rsz != sz) {
                                                puts("couldn't read lc");
                                                free(lc);
                                                continue;
                                            }
                                            void* sym = libinj_sym_findbin(inj, (uint32_t)imginfo[n].imageLoadAddress, (struct mach_header*)lc, name);
                                            if (sym && sym > imginfo[n].imageLoadAddress) {
                                                printf("[+] sym found: %p\n", sym);
                                                free(lc); free(data); free(bin);
                                                return sym;
                                            }
                                            
                                            free(lc);
                                        } else if (hdr.magic == MH_MAGIC) {
                                            sz += hdr.sizeofcmds;
                                            char* lc = malloc(sz);
                                            mach_vm_size_t rsz = sz;
                                            mach_vm_read_overwrite(inj, (uint32_t)imginfo[n].imageLoadAddress, sz, lc, &rsz);
                                            if (rsz != sz) {
                                                puts("couldn't read lc");
                                                free(lc);
                                                continue;
                                            }
                                            void* sym = libinj_sym_findbin(inj, (uint32_t)imginfo[n].imageLoadAddress, (struct mach_header*)lc, name);
                                            if (sym) {
                                                printf("[+] sym found: %x\n", sym);
                                                free(lc); free(data); free(bin);
                                                return sym;
                                            }
                                            free(lc);
                                        }
                                    }
                                    //
                                }
                                free(data);

                            }
                        } else if (*(uint32_t*) bin == MH_MAGIC_64) {
                            
                            struct mach_header_64* hd = (struct mach_header_64*) bin;
                            if (hd->filetype == MH_EXECUTE) {
                               // puts("main binary 64");
                            } else if (hd->filetype == MH_DYLINKER) {
                                //puts("dyld 64");
                                uint64_t dyld_img_info = libinj_sym_findbin(inj, address, (struct mach_header*)hd, "_dyld_all_image_infos");
                                if (!dyld_img_info) {
                                    puts("couldn't find dyld info");
                                    return 0;
                                }
                                uint64_t fileoff=0, vmaddr_slide=0;
                                void* data = map_segment(inj, -1, "__DATA", (void*)address, (struct mach_header*)hd, &fileoff, &vmaddr_slide);
                                if (!data) {
                                    return NULL;
                                }
                                struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)( (char*)data + dyld_img_info - fileoff - address);
                                
                                struct dyld_image_info* imginfo = (struct dyld_image_info* )((char*)data + (uint64_t)infos->infoArray - fileoff - address);
                                
                                for (int n=0; n < infos->infoArrayCount; n++) {
                                    //printf("=> binary found: %p\n",imginfo[n].imageLoadAddress);
                                    mach_vm_size_t sz=0;
                                    struct mach_header hdr;
                                    mach_vm_read_overwrite(inj, imginfo[n].imageLoadAddress, sizeof(struct mach_header), &hdr, &sz);
                                    if (sz != sizeof(struct mach_header)) {
                                        puts("couldn't read");
                                        return NULL;
                                    } else {
                                        if (hdr.magic == MH_MAGIC_64) {
                                            struct mach_header_64 hdr;
                                            mach_vm_read_overwrite(inj, imginfo[n].imageLoadAddress, sizeof(struct mach_header_64), &hdr, &sz);
                                            if (sz != sizeof(struct mach_header_64)) {
                                                puts("couldn't read");
                                                return NULL;
                                            }
                                            sz += hdr.sizeofcmds;
                                            char* lc = malloc(sz);
                                            mach_vm_size_t rsz = sz;
                                            mach_vm_read_overwrite(inj, imginfo[n].imageLoadAddress, sz, lc, &rsz);
                                            if (rsz != sz) {
                                                puts("couldn't read lc");
                                                free(lc);
                                                continue;
                                            }
                                            void* sym = libinj_sym_findbin(inj, (mach_vm_address_t)imginfo[n].imageLoadAddress, (struct mach_header*)lc, name);
                                            if (sym && sym > imginfo[n].imageLoadAddress) {
                                                printf("[+] sym found: %p\n", sym);
                                                free(lc); free(data); free(bin);
                                                return sym;
                                            }
                                            
                                            free(lc);
                                        } else if (hdr.magic == MH_MAGIC) {
                                            sz += hdr.sizeofcmds;
                                            char* lc = malloc(sz);
                                            mach_vm_size_t rsz = sz;
                                            mach_vm_read_overwrite(inj, (mach_vm_address_t)imginfo[n].imageLoadAddress, sz, lc, &rsz);
                                            if (rsz != sz) {
                                                puts("couldn't read lc");
                                                free(lc);
                                            }
                                            void* sym = libinj_sym_findbin(inj, (mach_vm_address_t)imginfo[n].imageLoadAddress, (struct mach_header*)lc, name);
                                            if (sym) {
                                                printf("[+] sym found: %x\n", sym);
                                                free(lc); free(data); free(bin);
                                                return sym;
                                            }
                                            free(lc);
                                        }
                                    }
                                    //
                                }
                                free(data);
                                
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

void* libinj_sym_findbin(inject_t task, void* addr, struct mach_header *mhi, const char *name) {
    if (mhi->magic == MH_MAGIC_64) {
        struct mach_header_64 *mh = (struct mach_header_64*)mhi;
        struct symtab_command *symtab = NULL;
        struct segment_command_64 *linkedit = NULL;

        /*
         * Find the LINKEDIT and SYMTAB sections
         */
        linkedit = find_segment_64(mh, SEG_LINKEDIT);
        if (!linkedit) {
            return (void*)NULL;
        }
        
        symtab = (struct symtab_command *)find_load_command_64(mh, LC_SYMTAB);
        if (!symtab) {
            return (void*)NULL;
        }
        uint64_t fileoff = 0;
        uint64_t vmaddr_slide = 0;
        void* linkedit_map = map_segment(task, -1, "__LINKEDIT", addr, mhi, &fileoff, &vmaddr_slide);
        if  (!linkedit_map) return 0;
        void* symtabp = symtab->stroff + 4 - fileoff + linkedit_map;
        void* symtabz = symtab->stroff  - fileoff + linkedit_map;
        void* symendp = symtab->stroff  - fileoff + linkedit_map + symtab->strsize - 0xA;
        uint32_t idx = 0;
        while (symtabp < symendp) {
            if(strcmp(symtabp, name) == 0) goto found;
            symtabp += strlen((char*)symtabp) + 1;
            idx++;
        }
        free(linkedit_map);
        return (void*)NULL;
    found:;
        struct nlist_64* nlp = (struct nlist_64*) (((uint32_t)(symtab->symoff))  - fileoff + linkedit_map);
        uint64_t strx = ((char*)symtabp - (char*)symtabz);
        unsigned int symp = 0;
        while(symp <= (symtab->nsyms)) {
            uint32_t strix = *((uint32_t*)nlp);
            if(strix == strx)
                goto found1;
            nlp ++; //sizeof(struct nlist_64);
            symp++;
        }
        return 0;
    found1:;
        //printf("[+] found symbol %s at 0x%016llx\n", name, nlp->n_value);
        void* ret_value =  (void*)nlp->n_value + vmaddr_slide;
        free(linkedit_map);
        return ret_value;

    } else if(mhi->magic == MH_MAGIC) {
        struct mach_header *mh = (struct mach_header*)mhi;
        struct symtab_command *symtab = NULL;
        struct segment_command *linkedit = NULL;
        
        /*
         * Find the LINKEDIT and SYMTAB sections
         */
        linkedit = find_segment(mh, SEG_LINKEDIT);
        if (!linkedit) {
            puts("no linkedit found");
            return (void*)NULL;
        }
        
        symtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
        if (!symtab) {
            return (void*)NULL;
        }
        uint64_t fileoff = 0;
        uint64_t vmaddr_slide = 0;
        void* linkedit_map = map_segment(task, -1, "__LINKEDIT", addr, mhi, &fileoff, &vmaddr_slide);
        if  (!linkedit_map) return 0;
        void* symtabp = symtab->stroff + 4 - fileoff + linkedit_map;
        void* symtabz = symtab->stroff  - fileoff + linkedit_map;
        void* symendp = symtab->stroff  - fileoff + linkedit_map + symtab->strsize - 0xA;
        uint32_t idx = 0;
        while (symtabp < symendp) {
            if(strcmp(symtabp, name) == 0) goto found32;
            symtabp += strlen((char*)symtabp) + 1;
            idx++;
        }
        free(linkedit_map);
        return (void*)NULL;
    found32:;
        struct nlist* nlp = (struct nlist*) (((uint32_t)(symtab->symoff))  - fileoff + linkedit_map);
        uint64_t strx = ((char*)symtabp - (char*)symtabz);
        unsigned int symp = 0;
        while(symp <= (symtab->nsyms)) {
            uint32_t strix = *((uint32_t*)nlp);
            if(strix == strx)
                goto found132;
            nlp ++; //sizeof(struct nlist_64);
            symp++;
        }
        return 0;
    found132:;
        //printf("[+] found symbol %s at 0x%016llx\n", name, nlp->n_value);
        uint32 ret_value =  nlp->n_value + vmaddr_slide;
        free(linkedit_map);
        return (void*)ret_value;

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



