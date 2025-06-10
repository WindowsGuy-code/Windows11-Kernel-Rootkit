#pragma once
#include "includes.hpp"

namespace k_hook
{
	// SSDT�ص�����
	typedef void(__fastcall* fssdt_call_back)(unsigned long ssdt_index, void** ssdt_address);

	// ��ʼ������
	bool initialize(fssdt_call_back ssdt_call_back);

	// ��ʼ���غ�������
	bool start();

	// �������غ�������
	bool stop();
}