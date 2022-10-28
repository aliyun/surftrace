//
// Created by 廖肇燕 on 2022/10/24.
//

#ifndef LBC_ELF_LOCAL_H
#define LBC_ELF_LOCAL_H

#define EI_NIDENT   16      /* Size of e_ident[] */

typedef struct elf_internal_ehdr {
    unsigned char     e_ident[EI_NIDENT]; /* ELF "magic number" */
    bfd_vma       e_entry;    /* Entry point virtual address */
    bfd_size_type     e_phoff;    /* Program header table file offset */
    bfd_size_type     e_shoff;    /* Section header table file offset */
    unsigned long     e_version;  /* Identifies object file version */
    unsigned long     e_flags;    /* Processor-specific flags */
    unsigned short    e_type;     /* Identifies object file type */
    unsigned short    e_machine;  /* Specifies required architecture */
    unsigned int      e_ehsize;   /* ELF header size in bytes */
    unsigned int      e_phentsize;    /* Program header table entry size */
    unsigned int      e_phnum;    /* Program header table entry count */
    unsigned int      e_shentsize;    /* Section header table entry size */
    unsigned int      e_shnum;    /* Section header table entry count */
    unsigned int      e_shstrndx; /* Section header string table index */
} Elf_Internal_Ehdr;


struct elf_internal_phdr {
    unsigned long p_type;         /* Identifies program segment type */
    unsigned long p_flags;        /* Segment flags */
    bfd_vma   p_offset;       /* Segment file offset */
    bfd_vma   p_vaddr;        /* Segment virtual address */
    bfd_vma   p_paddr;        /* Segment physical address */
    bfd_vma   p_filesz;       /* Segment size in file */
    bfd_vma   p_memsz;        /* Segment size in memory */
    bfd_vma   p_align;        /* Segment alignment, file & memory */
};

typedef struct elf_internal_phdr Elf_Internal_Phdr;

/* Section header */

typedef struct elf_internal_shdr {
    unsigned int  sh_name;        /* Section name, index in string tbl */
    unsigned int  sh_type;        /* Type of section */
    bfd_vma   sh_flags;       /* Miscellaneous section attributes */
    bfd_vma   sh_addr;        /* Section virtual addr at execution */
    file_ptr  sh_offset;      /* Section file offset */
    bfd_size_type sh_size;        /* Size of section in bytes */
    unsigned int  sh_link;        /* Index of another section */
    unsigned int  sh_info;        /* Additional section information */
    bfd_vma   sh_addralign;       /* Section alignment */
    bfd_size_type sh_entsize;     /* Entry size if section holds table */

    /* The internal rep also has some cached info associated with it. */
    asection *    bfd_section;        /* Associated BFD section.  */
    unsigned char *contents;      /* Section contents.  */
} Elf_Internal_Shdr;

struct elf_obj_tdata
{
    Elf_Internal_Ehdr elf_header[1];  /* Actual data, but ref like ptr */
    Elf_Internal_Shdr **elf_sect_ptr;
    Elf_Internal_Phdr *phdr;
    Elf_Internal_Shdr symtab_hdr;
    Elf_Internal_Shdr shstrtab_hdr;
    Elf_Internal_Shdr strtab_hdr;
    Elf_Internal_Shdr dynsymtab_hdr;
    Elf_Internal_Shdr dynstrtab_hdr;
    Elf_Internal_Shdr dynversym_hdr;
    Elf_Internal_Shdr dynverref_hdr;
    Elf_Internal_Shdr dynverdef_hdr;
};

#define elf_tdata(bfd)      ((bfd)->tdata.elf_obj_data)
#define elf_elfheader(bfd)	(elf_tdata(bfd)->elf_header)

#endif //LBC_ELF_LOCAL_H
