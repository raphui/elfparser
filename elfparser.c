/*
 * Copyright (C) 2015  Raphaël Poggi <poggi.raph@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "symbols.h"

#define ELF_ST_BIND(x)	((x) >> 4)

#define DEBUG_PRINTF	0

#define debug_printf(...) do{ if(DEBUG_PRINTF){ printf(__VA_ARGS__);}}while(0)

/*
 * S (when used on its own) is the address of the symbol.
 * A is the addend for the relocation.
 * P is the address of the place being relocated (derived from r_offset).
 * T is 1 if the target symbol S has type STT_FUNC and the symbol addresses a Thumb instruction; it is 0
 * otherwise.
 */

#define R_ARM_ABS32		2	/* (S + A) | T */
#define R_ARM_THM_CALL		10	/* ((S + A) | T) – P */
#define R_ARM_THM_MOVW_ABS_NC	47	/* (S + A) | T */
#define R_ARM_THM_MOVT_ABS	48	/* S + A */

static char *buff;
static int size;
static int section_size;
static Elf32_Ehdr *ehdr;
static Elf32_Shdr *symtab;
static Elf32_Shdr *strtab;

static Elf32_Shdr *elf_get_section(int num)
{
	return (Elf32_Shdr *)(buff + ehdr->e_shoff + num * section_size);
}

static int elf_get_symval(Elf32_Sym *sym)
{
	char *str;
	int addr;
	Elf32_Shdr *target;

	if (sym->st_shndx == SHN_UNDEF) {
		str = buff + strtab->sh_offset + sym->st_name;

		debug_printf("sym_value: %#x ", sym->st_value);
		debug_printf("sym: %s\n", str);

		addr = symbol_get_addr(str);
		if (addr == 0) {
			if (ELF32_ST_BIND(sym->st_info) & STB_WEAK)
				addr = 0;
			else {
				printf("[-] Undefined symbol: %s\n", str);
				addr = -ENXIO;
			}
		}
	} else if (sym->st_shndx == SHN_ABS) {
		addr = sym->st_value;
	} else {
		debug_printf("%d\n", sym->st_shndx);
		debug_printf("\t%d\n", ELF_ST_BIND(sym->st_info));

		if (sym->st_shndx == SHN_HIRESERVE) {
			target = elf_get_section(sym->st_shndx);
			addr = buff + sym->st_value + target->sh_offset;
		}
	}

	return addr;
}

static int elf_reloc(Elf32_Ehdr *ehdr, Elf32_Shdr *target, Elf32_Rel *rel)
{
	int addr = buff + target->sh_offset;
	int *ref = (int *)(addr + rel->r_offset);
	Elf32_Sym *sym;
	int func;
	int ret = 0;
	int s, a, p, t;

	if (ELF32_R_SYM(rel->r_info) != SHN_UNDEF) {
		sym = (Elf32_Sym *)(buff + symtab->sh_offset + ELF32_R_SYM(rel->r_info) * symtab->sh_entsize);
		func = elf_get_symval(sym);
		if (func < 0)
			return func;

		debug_printf("\t- target: %#x\n", addr);
		debug_printf("\t- reloff in target: %#p\n", ref);
		debug_printf("\t- func: %#x\n", func);

		if (!func) {
			debug_printf("[-] Failed to find address symbol\n");
			return -ENXIO;
		}
	}

	s = func;
	a = *ref;
	p = ref;
	t = func & 0x1;

	debug_printf("\t- %s instruction\n", t ? "Thumb" : "ARM");
	debug_printf("\t- before reloc: %#x\n", *ref);

	switch (ELF32_R_TYPE(rel->r_info)) {
	case R_ARM_ABS32:
		debug_printf("R_ARM_ABS32 reloc\n");
		*ref = (s + a) | t;
		break;
	case R_ARM_THM_CALL:
		debug_printf("R_ARM_THM_CALL reloc\n");
		*ref = ((s + a) | t) - p;
		break;
	case R_ARM_THM_MOVW_ABS_NC:
		debug_printf("R_ARM_THM_MOVW_ABS_NC reloc\n");
		*ref = (s + a) | t;
		break;
	case R_ARM_THM_MOVT_ABS:
		debug_printf("R_ARM_THM_MOVT_ABS reloc\n");
		*ref = s + a;
		break;
	default:
		return -EINVAL;
	}

	debug_printf("\t- after reloc: %#x\n", *ref);

	return ret;
}

int main(int argc, char **argv)
{
	int fd;
	char *str;
	Elf32_Shdr *shdr;
	Elf32_Shdr *section;
	Elf32_Shdr *target;
	Elf32_Rel *rel;
	struct stat sb;
	int i, j;
	int ret = 0;

	if (argc < 2)
		return -EINVAL;

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		printf("[-] Cannot open %s\n", argv[1]);
		return fd;
	}

	fstat(fd, &sb);
	size = sb.st_size;
	buff = (char *)mmap((caddr_t)NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buff < 0) {
		printf("[-] Cannot mmap file\n");
		close(fd);
		return errno;
	}

	printf("[+] %s mapped at %p (size: %d)\n", argv[1], buff, size);

	ehdr = (Elf32_Ehdr *)buff;

	printf("[+] Info: \n");
	printf("\t- bit format: %#x\n", ehdr->e_ident[EI_CLASS]);
	printf("\t- architecture: %#x\n", ehdr->e_machine);
	printf("\t- num section: %d\n", ehdr->e_shnum);
	printf("\t- index sections name: %d\n", ehdr->e_shstrndx);
	printf("\t- section header offset: %#x\n", ehdr->e_shoff);

	section_size = ehdr->e_shentsize;
	shdr = elf_get_section(ehdr->e_shstrndx);

	printf("\t- section string table offset: %#x\n", shdr->sh_offset);

	printf("[+] dumping section name: \n");
	for (i = 0; i < ehdr->e_shnum; i++) {
		section = elf_get_section(i);
		str = buff + shdr->sh_offset + section->sh_name;
		printf("[!] %s\n", str);

		if (!strcmp(str, ".symtab"))
			symtab = section;
		else if (!strcmp(str, ".strtab"))
			strtab = section;
	}

	printf("[+] dumping section needed relocation: \n");
	for (i = 0; i < ehdr->e_shnum; i++) {
		section = elf_get_section(i);
		str = buff + shdr->sh_offset + section->sh_name;
		if (section->sh_type == SHT_REL) {
			printf("[!] %s\n", str);
			for (j = 0; j < (section->sh_size / section->sh_entsize); j++) {
				rel = (Elf32_Rel *)(buff + section->sh_offset + j * section->sh_entsize);
				target = elf_get_section(section->sh_info);

				debug_printf("\t- offset: %#x ", rel->r_offset);
				debug_printf("info: %#x ", rel->r_info);
				debug_printf("\t- applies to: %#x\n", section->sh_info);

				ret = elf_reloc(ehdr, target, rel);
				if (ret < 0) {
					debug_printf("[-] Failed to reloc\n");
				}
			}
		}
	}
	

	munmap((caddr_t)buff, size);
	close(fd);

	return ret;
}
