#include <vector>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#define ACTION_ENABLE	0
#define ACTION_DISABLE	1

extern "C"
{
    #include "Ihook.h"
}

void ModifyIBored() __attribute__((constructor));
void before_main() __attribute__((constructor));

typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;     //����HOOK��

void before_main() {
    LOGI("Hook is auto loaded!\n");
}

/**
 * ����inline hook�ӿڣ��������inline hook��Ϣ
 * @param  pHookAddr     Ҫhook�ĵ�ַ
 * @param  onCallBack    Ҫ����Ļص�����
 * @return               inlinehook�Ƿ����óɹ����Ѿ����ù����ظ����÷���false��
 */
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct user_pt_regs *))
{
    bool bRet = false;
    LOGI("InlineHook");

    if(pHookAddr == NULL || onCallBack == NULL)
    {
        return bRet;
    }

    INLINE_HOOK_INFO* pstInlineHook = new INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

    if(HookArm(pstInlineHook) == false)
    {
        LOGI("HookArm fail.");
        delete pstInlineHook;
        return bRet;
    }

    
    gs_vecInlineHookInfo.push_back(pstInlineHook);
    return true;
}

/**
 * ����ӿڣ�����ȡ��inline hook
 * @param  pHookAddr Ҫȡ��inline hook��λ��
 * @return           �Ƿ�ȡ���ɹ��������ڷ���ȡ��ʧ�ܣ�
 */
bool UnInlineHook(void *pHookAddr)
{
    bool bRet = false;

    if(pHookAddr == NULL)
    {
        return bRet;
    }

    InlineHookInfoPVec::iterator itr = gs_vecInlineHookInfo.begin();
    InlineHookInfoPVec::iterator itrend = gs_vecInlineHookInfo.end();

    for (; itr != itrend; ++itr)
    {
        if (pHookAddr == (*itr)->pHookAddr)
        {
            INLINE_HOOK_INFO* pTargetInlineHookInfo = (*itr);

            gs_vecInlineHookInfo.erase(itr);
            if(pTargetInlineHookInfo->pStubShellCodeAddr != NULL)
            {
                delete pTargetInlineHookInfo->pStubShellCodeAddr;
            }
            if(pTargetInlineHookInfo->ppOldFuncAddr)
            {
                delete *(pTargetInlineHookInfo->ppOldFuncAddr);
            }
            delete pTargetInlineHookInfo;
            bRet = true;
        }
    }

    return bRet;
}


void EvilHookStubFunctionForIBored(user_pt_regs *regs)
{
    LOGI("In Evil Hook Stub.");
      regs->regs[9]=0x333;
}

void ModifyIBored()
{
    LOGI("In IHook's ModifyIBored.");

    int target_offset = 0x600; 

    void* pModuleBaseAddr = GetModuleBaseAddr(-1, "libhellojni.so"); 

    if(pModuleBaseAddr == 0)
    {
        LOGI("get module base error.");
        return;
    }
    
    uint64_t uiHookAddr = (uint64_t)pModuleBaseAddr + target_offset; //��ʵHook���ڴ��ַ

    
    InlineHook((void*)(uiHookAddr), EvilHookStubFunctionForIBored); //*�ڶ�����������Hook��Ҫ����Ĺ��ܴ�������*
}