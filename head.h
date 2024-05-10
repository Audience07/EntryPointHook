#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <locale.h>



//���ļ������仺�����������ļ�������ָ��
LPVOID _OpenFile(IN const LPSTR str, OUT size_t* FileSize);
//��ȡ�ļ���ʶ���洢��FileSign�ṹ�У����ؽڱ�����
size_t _ReadData(IN LPVOID FileBuffer, OUT struct FileSign* FileSign);
//��ȡ�ڱ�ؼ��ֶ�
void _ReadSectionTable(OUT struct SectionTable* pSectionTable, IN struct FileSign* pFileSign);
//���PE�ṹ�ؼ��ֶ�
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
LPVOID _vFileBuffer(IN LPVOID FileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
//��ת��EntryPoint����
//void _Run(IN struct FileSign* pFileSign, IN LPVOID vFileBuffer);
// 
//���ش������
size_t _FindCodeSection(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
//����д�õ�ImageBuffer��дΪFileBuffer,����NewBuffer��ָ��&&NewBuffer�Ĵ�С
LPVOID _NewBuffer(IN LPVOID vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, size_t SizeOfCode, OUT size_t* FileSize, IN size_t SizeOfNewSection);
//��NewBuffer����
void _SaveFile(IN LPVOID NewBuffer, IN size_t* FileSize, IN LPSTR New_FilePATH);
//д���µĽ�
void _AddNewSection(OUT LPVOID vFileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable, IN LPSTR SectionName, IN size_t SizeOfSection);



//���ɸ���,��shellcodeд�����ν�β
void _WriteShellCodeToIdleArea(OUT LPVOID vFileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable, IN char* shellcode, IN LPSTR SizeOfCode);






//PE����ѡPEͷ
struct FileSign {
	//��λָ��
	LPVOID NTHeader;
	LPVOID PEHeader;
	LPVOID OptionalHeader;

	//PEͷ
	DWORD MZHeader;
	WORD Machine;
	WORD NumberOfSection;
	DWORD SizeOfOptionHeader;

	//��ѡPEͷ
	WORD Magic;
	DWORD EntryPoint;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
};


//�ڱ�
struct SectionTable {
	LPVOID Point;
	char name[9];
	DWORD VirtualSize;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointToRawData;
	DWORD Characteristics;
};



