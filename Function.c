#include "head.h"



//打开文件，分配缓冲区，返回文件缓冲区指针
//如准备添加新节，请在最后一个参数填入新节的大小
LPVOID _OpenFile(IN const LPSTR str, OUT size_t* FileSize, IN size_t SizeOfNewSection) {
	FILE* pf = fopen(str, "rb");
	if (!pf) {
		perror("打开文件失败");
		return NULL;
	}
	fseek(pf, 0, SEEK_END);
	*FileSize = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	LPVOID FileBuffer = malloc(*(FileSize)+= SizeOfNewSection);
	if (!FileBuffer) {
		printf("分配空间失败\n");
		fclose(pf);
		free(FileBuffer);
		return 0;
	}

	fread(FileBuffer, 1, *FileSize, pf);
	if (!FileBuffer) {
		printf("读取内存失败\n");
		fclose(pf);
		free(FileBuffer);
		return 0;
	}
	fclose(pf);
	return FileBuffer;

}





//读取文件标识，存储到FileSign结构中，返回节表数量
size_t _ReadData(LPVOID FileBuffer, struct FileSign* FileSign) {
	FileSign->MZHeader = *(WORD*)((char*)FileBuffer);
	if (FileSign->MZHeader != 0x5a4d) {
		return 0;
	}
	//定位指针
	FileSign->NTHeader = (char*)((char*)FileBuffer + (*(DWORD*)((char*)FileBuffer + 0x3C)));
	FileSign->PEHeader = (char*)((char*)FileSign->NTHeader + 0x4);
	FileSign->OptionalHeader = (char*)((char*)FileSign->NTHeader + 0x18);

	//PE头
	FileSign->Machine = *(WORD*)((char*)FileSign->PEHeader);
	FileSign->NumberOfSection = *(WORD*)((char*)FileSign->PEHeader + 0x2);
	FileSign->SizeOfOptionHeader = *(WORD*)((char*)FileSign->PEHeader + 0x10);

	//可选PE头
	FileSign->Magic = *(WORD*)((char*)FileSign->OptionalHeader);
	FileSign->EntryPoint = *(DWORD*)((char*)FileSign->OptionalHeader + 0x10);
	FileSign->ImageBase = *(DWORD*)((char*)FileSign->OptionalHeader + 0x1C);
	FileSign->SectionAlignment = *(DWORD*)((char*)FileSign->OptionalHeader + 0x20);
	FileSign->FileAlignment = *(DWORD*)((char*)FileSign->OptionalHeader + 0x24);
	FileSign->SizeOfImage = *(DWORD*)((char*)FileSign->OptionalHeader + 0x38);
	FileSign->SizeOfHeaders = *(DWORD*)((char*)FileSign->OptionalHeader + 0x3C);

	//返回节表数量
	return 1;
}






//读取节表关键字段
void _ReadSectionTable(OUT struct SectionTable* pSectionTable,IN struct FileSign* pFileSign) {
	for (int i = 0; i < pFileSign->NumberOfSection;i++, pSectionTable++) {
		pSectionTable->Point = (char*)((char*)pFileSign->OptionalHeader + pFileSign->SizeOfOptionHeader+(i*0x28));
		memcpy(pSectionTable->name, pSectionTable->Point, 8);
		pSectionTable->VirtualSize = *(DWORD*)((char*)pSectionTable->Point + 0x8);
		pSectionTable->VirtualAddress = *(DWORD*)((char*)pSectionTable->Point + 0xC);
		pSectionTable->SizeOfRawData = *(DWORD*)((char*)pSectionTable->Point + 0x10);
		pSectionTable->PointToRawData = *(DWORD*)((char*)pSectionTable->Point + 0x14);
		pSectionTable->Characteristics = *(DWORD*)((char*)pSectionTable->Point + 0x24);
	}
}


//将缓冲区的文件读取到分配的可执行可读写内存里
LPVOID _vFileBuffer(IN LPVOID FileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable) {
	LPVOID vFileBuffer = VirtualAlloc(NULL, pFileSign->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!vFileBuffer) {
		return NULL;
	}
	memset(vFileBuffer, 0, pFileSign->SizeOfImage);
	memcpy(vFileBuffer, FileBuffer, pFileSign->SizeOfHeaders);
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		memcpy(((char*)vFileBuffer + pSectionTable->VirtualAddress), ((char*)FileBuffer + pSectionTable->PointToRawData), pSectionTable->VirtualSize);
		pSectionTable++;
	}
	return vFileBuffer;

}


//跳转至EntryPoint运行
void _Run(IN struct FileSign* pFileSign, IN LPVOID vFileBuffer) {
	DWORD EntryPoint = (char*)vFileBuffer + pFileSign->EntryPoint;
	_asm{
		mov eax, EntryPoint;
		jmp eax;
	}

}



//返回代码节数
size_t _FindCodeSection(IN struct FileSign* pFileSign,IN struct SectionTable* pSectionTable) {
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		if ((pFileSign->EntryPoint > pSectionTable->VirtualAddress) && (pFileSign->EntryPoint < (pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData))) {
			return i;
		}
		pSectionTable++;
	}
}


//不可复用,将shellcode写入代码段结尾
void _WriteShellCodeToIdleArea(OUT LPVOID vFileBuffer,IN struct FileSign* pFileSign,IN struct SectionTable* pSectionTable,IN char* shellcode , IN size_t SizeOfCode) {
	//判断代码节
	size_t n = _FindCodeSection(pFileSign, pSectionTable);
	pSectionTable += n;

	
	//判断剩余空间是否够填入shellcode
	LPVOID BeginCode = ((char*)vFileBuffer + pSectionTable->VirtualAddress + pSectionTable->VirtualSize);
	if (SizeOfCode >= ((DWORD)vFileBuffer + (pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData) - (DWORD)BeginCode)) {
		printf("代码段剩余空间不足\n");
		return;
	}

	//填写shellcode
	memcpy(BeginCode, shellcode, SizeOfCode);


	//跳转根据ImageBuffer计算
	//修正call		FunctionAddress-(BeginCode+Push+5-ImageBuffer+ImageBase)	MessageBoxA在内存中的偏移
	LPVOID CallOffsetAddr = (char*)BeginCode + 0x8 + 0x1;
	*(DWORD*)CallOffsetAddr = (DWORD)MessageBoxA - ((DWORD)CallOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//修正jmp		OEP-(BeginCode+Push+Call+Jmp-ImageBuffer+ImageBase)			OEP在内存中的偏移
	LPVOID JmpOffsetAddr = (DWORD)CallOffsetAddr + 0x4 + 0x1;
	*(DWORD*)JmpOffsetAddr = (pFileSign->EntryPoint + pFileSign->ImageBase) - ((DWORD)JmpOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//修正OEP
	//EntryPoint 代码起始的偏移
	LPVOID pOEP = (DWORD)vFileBuffer + (*(DWORD*)((DWORD)vFileBuffer + 0x3C)) + (0x18 + 0x10);
	*(DWORD*)pOEP = (DWORD)BeginCode - (DWORD)vFileBuffer;

}


//把Shellcode写入新分配的节中
void _WriteShellCodeToNewSection(OUT LPVOID vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, IN LPSTR ShellCode, IN size_t SizeOfShellcode) {

	//定位新节的位置
	pSectionTable += pFileSign->NumberOfSection - 1;
	LPVOID pNewSection = (DWORD)vFileBuffer + pSectionTable->VirtualAddress;

	//全部填0
	memset(pNewSection, 0, pSectionTable->SizeOfRawData);

	//CopyShellcode
	memcpy(pNewSection, ShellCode, SizeOfShellcode);

	//跳转根据ImageBuffer计算
	//修正call		FunctionAddress-(BeginCode+Push+5-ImageBuffer+ImageBase)	MessageBoxA在内存中的偏移
	LPVOID CallOffsetAddr = (char*)pNewSection + 0x8 + 0x1;
	*(DWORD*)CallOffsetAddr = (DWORD)MessageBoxA - ((DWORD)CallOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//修正jmp		OEP-(BeginCode+Push+Call+Jmp-ImageBuffer+ImageBase)			OEP在内存中的偏移
	LPVOID JmpOffsetAddr = (DWORD)CallOffsetAddr + 0x4 + 0x1;
	*(DWORD*)JmpOffsetAddr = (pFileSign->EntryPoint + pFileSign->ImageBase) - ((DWORD)JmpOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//修正OEP
	//EntryPoint 代码起始的偏移
	LPVOID pOEP = (DWORD)vFileBuffer + (*(DWORD*)((DWORD)vFileBuffer + 0x3C)) + (0x18 + 0x10);
	*(DWORD*)pOEP = (DWORD)pNewSection - (DWORD)vFileBuffer;
}




//写入新的节，需传入ImageBuffer，Header头，节表数据，新节的名字
void _AddNewSection(OUT LPVOID FileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable, IN LPSTR SectionName,IN size_t SizeOfSection) {
	//单个节表占40字节
	//判断空间是否够80字节来分配新的节表
	LPVOID pNewSectionTable = (DWORD)FileBuffer + (*(DWORD*)((DWORD)FileBuffer + 0x3C)) + 0x18 + pFileSign->SizeOfOptionHeader + (pFileSign->NumberOfSection * 40);
	if (((pFileSign->SizeOfHeaders + (DWORD)FileBuffer) - (DWORD)pNewSectionTable) < 80) {
		printf("没有足够的空间分配新的节表\n");
		return;
	}

	//NumberOfSection + 1
	LPSTR pvNumberOfSection = (WORD*)((DWORD)FileBuffer + *(DWORD*)((DWORD)FileBuffer + 0x3C) + 0x6);
	*(WORD*)pvNumberOfSection += 1;

	//修改SizeOfImage,加新增字节大小
	LPSTR pvSizeOfImage = (DWORD*)((DWORD)pvNumberOfSection + 0x12 + 0x38);
	*(DWORD*)pvSizeOfImage += SizeOfSection;

	//复制节表
	LPVOID pvBeginSectionTable = (DWORD)pvNumberOfSection + 0x12 + pFileSign->SizeOfOptionHeader;
	LPVOID pvCodeSection = (DWORD)pvBeginSectionTable + (_FindCodeSection(pFileSign, pSectionTable) * 40);
	LPVOID pvNewSection = (DWORD)pvBeginSectionTable + (pFileSign->NumberOfSection * 40);
	memcpy(pvNewSection, pvCodeSection, 40);


	//定位节表为新节上一个节
	pSectionTable += pFileSign->NumberOfSection - 1;


	//修改节表字段
	memset(pvNewSection, 0, 8);
	memcpy(pNewSectionTable, SectionName, 8);

	*(DWORD*)((DWORD)pvNewSection + 0x8) = SizeOfSection;
	*(DWORD*)((DWORD)pvNewSection + 0x0c) = pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData;
	*(DWORD*)((DWORD)pvNewSection + 0x10) = SizeOfSection;
	*(DWORD*)((DWORD)pvNewSection + 0x14) = pSectionTable->PointToRawData + pSectionTable->SizeOfRawData;

}




//释放ImageBuffer
//将ImageBuffer还原为FileBuffer
LPVOID _NewBuffer(IN LPVOID vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, IN size_t SizeOfCode, OUT size_t* FileSize) {
	//分配内存
	LPVOID NewBuffer = malloc(*FileSize);
	if (!NewBuffer) {
		printf("分配内存失败\n");
		free(NewBuffer);
		return NULL;
	}
	memset(NewBuffer, 0, *FileSize);
	//copyPE头
	memcpy(NewBuffer, vFileBuffer, pFileSign->SizeOfHeaders);

	//循环copy节表
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		if (i == _FindCodeSection(pFileSign, pSectionTable)) {
			pSectionTable->VirtualSize += SizeOfCode;
		}
		memcpy((DWORD)NewBuffer + pSectionTable->PointToRawData, (DWORD)vFileBuffer + pSectionTable->VirtualAddress, pSectionTable->VirtualSize);
		pSectionTable++;
	}
	return NewBuffer;
}



//将NewBuffer存盘
void _SaveFile(IN LPVOID NewBuffer, IN size_t* FileSize, IN LPSTR New_FilePATH) {
	FILE* pf = fopen(New_FilePATH, "wb");
	if (!pf) {
		perror("创建文件失败");
		fclose(pf);
		return;
	}
	if (!fwrite(NewBuffer, *FileSize, 1, pf)) {
		perror("写入失败");
		fclose(pf);
		return;
	}
	printf("存盘成功\n");
	fclose(pf);
	return;
}




//输出PE结构关键字段
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable) {
	printf("**********************************************************\n");
	printf("PE头:\n\n");
	//输出PE头
	printf("Machine:0x%x\n", pFileSign->Machine);
	printf("NumberOfSection:0x%x\n", pFileSign->NumberOfSection);
	printf("SizeOfOptionHeader:0x%x\n\n", pFileSign->SizeOfOptionHeader);

	//输出可选PE头
	printf("可选PE头:\n\n");
	printf("Magic:0x%x\n", pFileSign->Magic);
	printf("EntryPoint:0x%x\n", pFileSign->EntryPoint);
	printf("ImageBase:0x%x\n", pFileSign->ImageBase);
	printf("SectionAlignment:0x%x\n", pFileSign->SectionAlignment);
	printf("FileAlignment:0x%x\n", pFileSign->FileAlignment);
	printf("SizeOfImage:0x%x\n", pFileSign->SizeOfImage);
	printf("SizeOfHeaders:0x%x\n\n", pFileSign->SizeOfHeaders);

	printf("节表:\n\n");
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		printf("name:%s\n", pSectionTable->name);
		printf("VirtualSize:0x%x\n", pSectionTable->VirtualSize);
		printf("VirtualAddress:0x%x\n", pSectionTable->VirtualAddress);
		printf("SizeOfRawData:0x%x\n", pSectionTable->SizeOfRawData);
		printf("PointToRawData:0x%x\n", pSectionTable->PointToRawData);
		printf("Characteristics:0x%x\n\n", pSectionTable->Characteristics);
		pSectionTable++;
	}
	printf("**********************************************************\n");
	system("pause");
}