#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <locale.h>



//打开文件，分配缓冲区，返回文件缓冲区指针
LPVOID _OpenFile(IN const LPSTR str, OUT size_t* FileSize);
//读取文件标识，存储到FileSign结构中，返回节表数量
size_t _ReadData(IN LPVOID FileBuffer, OUT struct FileSign* FileSign);
//读取节表关键字段
void _ReadSectionTable(OUT struct SectionTable* pSectionTable, IN struct FileSign* pFileSign);
//输出PE结构关键字段
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
LPVOID _vFileBuffer(IN LPVOID FileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
//跳转至EntryPoint运行
//void _Run(IN struct FileSign* pFileSign, IN LPVOID vFileBuffer);
// 
//返回代码节数
size_t _FindCodeSection(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable);
//将改写好的ImageBuffer重写为FileBuffer,返回NewBuffer的指针&&NewBuffer的大小
LPVOID _NewBuffer(IN LPVOID vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, size_t SizeOfCode, OUT size_t* FileSize, IN size_t SizeOfNewSection);
//将NewBuffer存盘
void _SaveFile(IN LPVOID NewBuffer, IN size_t* FileSize, IN LPSTR New_FilePATH);
//写入新的节
void _AddNewSection(OUT LPVOID vFileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable, IN LPSTR SectionName, IN size_t SizeOfSection);



//不可复用,将shellcode写入代码段结尾
void _WriteShellCodeToIdleArea(OUT LPVOID vFileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable, IN char* shellcode, IN LPSTR SizeOfCode);






//PE，可选PE头
struct FileSign {
	//定位指针
	LPVOID NTHeader;
	LPVOID PEHeader;
	LPVOID OptionalHeader;

	//PE头
	DWORD MZHeader;
	WORD Machine;
	WORD NumberOfSection;
	DWORD SizeOfOptionHeader;

	//可选PE头
	WORD Magic;
	DWORD EntryPoint;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
};


//节表
struct SectionTable {
	LPVOID Point;
	char name[9];
	DWORD VirtualSize;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointToRawData;
	DWORD Characteristics;
};



