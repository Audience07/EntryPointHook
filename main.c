#include "head.h"
#define FilePATH "E:/C32Asm.exe"
#define New_FilePATH "E:/C32Asm_Protected.exe"
#define SizeOfCode 18
#define SizeOfNewSection 0x1000

//ѹ�ĸ����ջ������MessageBoxA�Ĳ�����Call��תMessageBoxAִ�к�����ִ�����Jmp��ת�����뿪ʼλ��
char shellcode[] = { 0x6A,0x02,0x6A,0x00,0x6A,0x00,0x6A,0x00,0xE8,0x00,0x00,0x00,0x00,0xE9,0x00,0x00,0x00,0x00 };



int main() {
	size_t* FileSize = malloc(sizeof(size_t));
	if (!FileSize) {
		printf("���ڿռ䲻��\n");
		return 0;
	}
	//��������,�����ʽ
	setlocale(LC_ALL, "chs");
	//���ļ�,��ȡFileBuffer
	size_t* FileBuffer = _OpenFile(FilePATH, FileSize,SizeOfNewSection);
	if (!FileBuffer) {
		return 0;
	}

	//�����ļ�������
	struct FileSign* pFileSign = malloc(sizeof(struct FileSign));
	if (!pFileSign) {
		printf("�����ڴ�ʧ��\n");
		system("pause");
		return 0;
	}
	//��ȡ�ļ��ؼ��ֶ�
	_ReadData(FileBuffer, pFileSign);


	//��ȡ�ڱ�ؼ��ֶ�
	struct SectionTable* pSectionTable = malloc(sizeof(struct SectionTable) * (pFileSign->NumberOfSection + 1));
	if (!pSectionTable) {
		printf("����ڱ��ڴ�ʧ��\n");
		system("pause");
		return 0;
	}
	_ReadSectionTable(pSectionTable,pFileSign);

	//ΪFileBuffer�����½ڱ�
	_AddNewSection(FileBuffer, pFileSign, pSectionTable, ".New", SizeOfNewSection);


	//���¶�ȡ����ڱ����ֶ�
	_ReadData(FileBuffer, pFileSign);
	_ReadSectionTable(pSectionTable, pFileSign);


	//�����ִ�е��ڴ棬�����������ڴ��������
	LPVOID vFileBuffer = _vFileBuffer(FileBuffer, pFileSign, pSectionTable);
	if (!vFileBuffer) {
		printf("����vFileBufferʧ��\n");
		system("pause");
		return 0;
	}

	//��Shellcodeд���·���Ľ���
	_WriteShellCodeToNewSection(vFileBuffer, pSectionTable, pFileSign, shellcode, SizeOfCode);
	


	

	



	//��ImageBufferת����FileBuffer,Ϊ������׼��
	LPVOID NewBuffer = _NewBuffer(vFileBuffer, pSectionTable, pFileSign, SizeOfCode, FileSize);



	//NewBuffer��ԭ�ɹ����ͷ�ImageBuffer
	VirtualFree(vFileBuffer,pFileSign->SizeOfImage,MEM_COMMIT|MEM_RESERVE);
	vFileBuffer = NULL;
	
	//����
	_SaveFile(NewBuffer, FileSize, New_FilePATH);



	//�ͷ��ڴ�
	free(NewBuffer);
	free(FileSize);
	free(pFileSign);
	free(pSectionTable);
}