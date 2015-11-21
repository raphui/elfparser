#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>


int main(int argc, char **argv)
{
	int fd, size;
	char *buff;
	char *str;
	char *s_entry;
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;
	Elf32_Shdr *section;
	Elf32_Shdr *target;
	Elf32_Shdr *symtab;
	Elf32_Shdr *strtab;
	Elf32_Rel *rel;
	Elf32_Sym *sym;
	struct stat sb;
	int i, j;
	int section_size;
	int addr;

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
	shdr = (Elf32_Shdr *)(buff + ehdr->e_shoff + section_size * ehdr->e_shstrndx);

	printf("\t- section string table offset: %#x\n", shdr->sh_offset);

	printf("[+] dumping section name: \n");
	for (i = 0; i < ehdr->e_shnum; i++) {
		section = (Elf32_Shdr *)(buff + ehdr->e_shoff + i * section_size);
		str = buff + shdr->sh_offset + section->sh_name;
		printf("[!] %s\n", str);

		if (!strcmp(str, ".symtab"))
			symtab = section;
		else if (!strcmp(str, ".strtab"))
			strtab = section;
	}

	printf("[+] dumping section needed relocation: \n");
	for (i = 0; i < ehdr->e_shnum; i++) {
		section = (Elf32_Shdr *)(buff + ehdr->e_shoff + i * section_size);
		str = buff + shdr->sh_offset + section->sh_name;
		if (section->sh_type == SHT_REL) {
			printf("[!] %s\n", str);
			for (j = 0; j < (section->sh_size / section->sh_entsize); j++) {
				rel = (Elf32_Rel *)(buff + section->sh_offset + j * section->sh_entsize);
				target = (Elf32_Shdr *)(buff + ehdr->e_shoff + section->sh_info * section->sh_entsize);
				addr = buff + target->sh_offset;
				sym = (Elf32_Sym *)(buff + symtab->sh_offset + ELF32_R_SYM(rel->r_info) * symtab->sh_entsize);
				str = buff + strtab->sh_offset + sym->st_name;

				printf("\t- offset: %#x ", rel->r_offset);
				printf("info: %#x ", rel->r_info);
				printf("sym_value: %#x ", sym->st_value);
				printf("sym: %s\n", str);
				printf("\t- applies to: %#x\n", section->sh_info);
				printf("\t- target: %#x\n", addr);
				printf("\t- reloffset in target: %#x\n", addr + rel->r_offset);
			}
		}
	}
	

	munmap((caddr_t)buff, size);
	close(fd);

	return 1;
}
