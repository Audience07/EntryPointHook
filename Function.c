#include "head.h"



//���ļ������仺�����������ļ�������ָ��
LPVOID _OpenFile(IN const char* str,OUT size_t *FileSize) {
	FILE* pf = fopen(str, "rb");
	if (!pf) {
		perror("���ļ�ʧ��");
		return NULL;
	}
	fseek(pf, 0, SEEK_END);
	*FileSize = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	LPVOID FileBuffer = (char*)malloc(*FileSize);
	if (!FileBuffer) {
		printf("����ռ�ʧ��\n");
		fclose(pf);
		free(FileBuffer);
		return 0;
	}

	fread(FileBuffer, 1, *FileSize, pf);
	if (!FileBuffer) {
		printf("��ȡ�ڴ�ʧ��\n");
		fclose(pf);
		free(FileBuffer);
		return 0;
	}
	fclose(pf);
	return FileBuffer;

}





//��ȡ�ļ���ʶ���洢��FileSign�ṹ�У����ؽڱ�����
size_t _ReadData(LPVOID FileBuffer, struct FileSign* FileSign) {
	FileSign->MZHeader = *(WORD*)((char*)FileBuffer);
	if (FileSign->MZHeader != 0x5a4d) {
		return 0;
	}
	//��λָ��
	FileSign->NTHeader = (char*)((char*)FileBuffer + (*(DWORD*)((char*)FileBuffer + 0x3C)));
	FileSign->PEHeader = (char*)((char*)FileSign->NTHeader + 0x4);
	FileSign->OptionalHeader = (char*)((char*)FileSign->NTHeader + 0x18);

	//PEͷ
	FileSign->Machine = *(WORD*)((char*)FileSign->PEHeader);
	FileSign->NumberOfSection = *(WORD*)((char*)FileSign->PEHeader + 0x2);
	FileSign->SizeOfOptionHeader = *(WORD*)((char*)FileSign->PEHeader + 0x10);

	//��ѡPEͷ
	FileSign->Magic = *(WORD*)((char*)FileSign->OptionalHeader);
	FileSign->EntryPoint = *(DWORD*)((char*)FileSign->OptionalHeader + 0x10);
	FileSign->ImageBase = *(DWORD*)((char*)FileSign->OptionalHeader + 0x1C);
	FileSign->SectionAlignment = *(DWORD*)((char*)FileSign->OptionalHeader + 0x20);
	FileSign->FileAlignment = *(DWORD*)((char*)FileSign->OptionalHeader + 0x24);
	FileSign->SizeOfImage = *(DWORD*)((char*)FileSign->OptionalHeader + 0x38);
	FileSign->SizeOfHeaders = *(DWORD*)((char*)FileSign->OptionalHeader + 0x3C);

	//���ؽڱ�����
	return 1;
}






//��ȡ�ڱ�ؼ��ֶ�
void _ReadSectionTable(struct SectionTable* pSectionTable,struct FileSign* pFileSign) {
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


//��ת��EntryPoint����
//void _Run(IN struct FileSign* pFileSign, IN LPVOID vFileBuffer) {
//	
//	DWORD EntryPoint = (char*)vFileBuffer + pFileSign->EntryPoint;
//	_asm{
//		mov eax, EntryPoint;
//		jmp eax;
//	}
//
//}



//���ش������
size_t _FindCodeSection(IN struct FileSign* pFileSign,IN struct SectionTable* pSectionTable) {
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		if ((pFileSign->EntryPoint > pSectionTable->VirtualAddress) && (pFileSign->EntryPoint < (pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData))) {
			return i;
		}
		pSectionTable++;
	}
}


//���ɸ���,��shellcodeд�����ν�β
void _WriteShellCode(OUT LPVOID vFileBuffer,IN struct FileSign* pFileSign,IN struct SectionTable* pSectionTable,IN char* shellcode , IN LPSTR SizeOfCode) {
	//�жϴ����
	size_t n = _FindCodeSection(pFileSign, pSectionTable);
	pSectionTable += n;

	//FileSign�����FileBuffer�ģ�����޷�д��ImageBase
	//******************************************************************************************************************
	//�ж�ʣ��ռ��Ƿ�����shellcode
	LPVOID BeginCode = ((char*)vFileBuffer + pSectionTable->VirtualAddress + pSectionTable->VirtualSize);
	if (SizeOfCode >= ((DWORD)vFileBuffer + (pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData) - (DWORD)BeginCode)) {
		printf("�����ʣ��ռ䲻��\n");
		return;
	}

	//��дshellcode
	memcpy(BeginCode, shellcode, SizeOfCode);


	//��ת����ImageBuffer����
	//����call		FunctionAddress-(BeginCode+Push+5-ImageBuffer+ImageBase)	MessageBoxA���ڴ��е�ƫ��
	LPVOID CallOffsetAddr = (char*)BeginCode + 0x8 + 0x1;
	*(DWORD*)CallOffsetAddr = (DWORD)MessageBoxA - ((DWORD)CallOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//����jmp		OEP-(BeginCode+Push+Call+Jmp-ImageBuffer+ImageBase)			OEP���ڴ��е�ƫ��
	LPVOID JmpOffsetAddr = (DWORD)CallOffsetAddr + 0x4 + 0x1;
	*(DWORD*)JmpOffsetAddr = (pFileSign->EntryPoint + pFileSign->ImageBase) - ((DWORD)JmpOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//����OEP
	//EntryPoint ������ʼ��ƫ��
	LPVOID pOEP = (DWORD)vFileBuffer + (*(DWORD*)((DWORD)vFileBuffer + 0x3C)) + (0x18 + 0x10);
	*(DWORD*)pOEP = (DWORD)BeginCode - (DWORD)vFileBuffer;

}




//******************************************************************************************************************


//�ͷ�ImageBuffer
//��ImageBuffer��ԭΪFileBuffer
LPVOID _NewBuffer(IN LPVOID vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, size_t SizeOfCode, OUT size_t FileSize) {
	//�����ڴ�
	LPVOID NewBuffer = (char*)malloc(FileSize);
	if (!NewBuffer) {
		printf("�����ڴ�ʧ��\n");
		free(NewBuffer);
		return NULL;
	}
	memset(NewBuffer, 0, FileSize);
	//copyPEͷ
	memcpy(NewBuffer, vFileBuffer, pFileSign->SizeOfHeaders);

	//ѭ��copy�ڱ�
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		if (i == _FindCodeSection(pFileSign, pSectionTable)) {
			pSectionTable->VirtualSize += SizeOfCode;
		}
		memcpy((DWORD)NewBuffer + pSectionTable->PointToRawData, (DWORD)vFileBuffer + pSectionTable->VirtualAddress, pSectionTable->VirtualSize);
		pSectionTable++;
	}
	return NewBuffer;
}



//��NewBuffer����
void _SaveFile(IN LPVOID NewBuffer, IN size_t FileSize,IN LPSTR New_FilePATH) {
	FILE* pf = fopen(New_FilePATH, "wb");
	if (!pf) {
		perror("�����ļ�ʧ��");
		fclose(pf);
		return;
	}
	if (!fwrite(NewBuffer, FileSize, 1, pf)) {
		perror("д��ʧ��");
		fclose(pf);
		return;
	}
	printf("���̳ɹ�\n");
	fclose(pf);
	return;
}




//���PE�ṹ�ؼ��ֶ�
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable) {
	printf("**********************************************************\n");
	printf("PEͷ:\n\n");
	//���PEͷ
	printf("Machine:0x%x\n", pFileSign->Machine);
	printf("NumberOfSection:0x%x\n", pFileSign->NumberOfSection);
	printf("SizeOfOptionHeader:0x%x\n\n", pFileSign->SizeOfOptionHeader);

	//�����ѡPEͷ
	printf("��ѡPEͷ:\n\n");
	printf("Magic:0x%x\n", pFileSign->Magic);
	printf("EntryPoint:0x%x\n", pFileSign->EntryPoint);
	printf("ImageBase:0x%x\n", pFileSign->ImageBase);
	printf("SectionAlignment:0x%x\n", pFileSign->SectionAlignment);
	printf("FileAlignment:0x%x\n", pFileSign->FileAlignment);
	printf("SizeOfImage:0x%x\n", pFileSign->SizeOfImage);
	printf("SizeOfHeaders:0x%x\n\n", pFileSign->SizeOfHeaders);

	printf("�ڱ�:\n\n");
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