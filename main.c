#include "head.h"
#define FilePATH "E:/C32Asm.exe"
#define New_FilePATH "E:/C32Asm_Protected.exe"
#define SizeOfCode 18
#define SizeOfNewSection 0x1000

//压四个零进栈，当作MessageBoxA的参数，Call跳转MessageBoxA执行函数，执行完后Jmp跳转到代码开始位置
char shellcode[] = { 0x6A,0x02,0x6A,0x00,0x6A,0x00,0x6A,0x00,0xE8,0x00,0x00,0x00,0x00,0xE9,0x00,0x00,0x00,0x00 };



int main() {
	size_t* FileSize = malloc(sizeof(size_t));
	if (!FileSize) {
		printf("堆内空间不足\n");
		return 0;
	}
	//设置区域,编码格式
	setlocale(LC_ALL, "chs");
	//打开文件,获取FileBuffer
	size_t* FileBuffer = _OpenFile(FilePATH, FileSize,SizeOfNewSection);
	if (!FileBuffer) {
		return 0;
	}

	//分配文件缓冲区
	struct FileSign* pFileSign = malloc(sizeof(struct FileSign));
	if (!pFileSign) {
		printf("分配内存失败\n");
		system("pause");
		return 0;
	}
	//读取文件关键字段
	_ReadData(FileBuffer, pFileSign);


	//读取节表关键字段
	struct SectionTable* pSectionTable = malloc(sizeof(struct SectionTable) * (pFileSign->NumberOfSection + 1));
	if (!pSectionTable) {
		printf("分配节表内存失败\n");
		system("pause");
		return 0;
	}
	_ReadSectionTable(pSectionTable,pFileSign);

	//为FileBuffer分配新节表
	_AddNewSection(FileBuffer, pFileSign, pSectionTable, ".New", SizeOfNewSection);


	//重新读取分配节表后的字段
	_ReadData(FileBuffer, pFileSign);
	_ReadSectionTable(pSectionTable, pFileSign);


	//分配可执行的内存，并将数据以内存对齐填入
	LPVOID vFileBuffer = _vFileBuffer(FileBuffer, pFileSign, pSectionTable);
	if (!vFileBuffer) {
		printf("分配vFileBuffer失败\n");
		system("pause");
		return 0;
	}

	//将Shellcode写入新分配的节中
	_WriteShellCodeToNewSection(vFileBuffer, pSectionTable, pFileSign, shellcode, SizeOfCode);
	


	

	



	//将ImageBuffer转换成FileBuffer,为存盘做准备
	LPVOID NewBuffer = _NewBuffer(vFileBuffer, pSectionTable, pFileSign, SizeOfCode, FileSize);



	//NewBuffer还原成功后释放ImageBuffer
	VirtualFree(vFileBuffer,pFileSign->SizeOfImage,MEM_COMMIT|MEM_RESERVE);
	vFileBuffer = NULL;
	
	//存盘
	_SaveFile(NewBuffer, FileSize, New_FilePATH);



	//释放内存
	free(NewBuffer);
	free(FileSize);
	free(pFileSign);
	free(pSectionTable);
}