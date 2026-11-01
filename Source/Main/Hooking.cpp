#include "Hooking.hpp"
#include "Logger.hpp"
#include "D3DRenderer.hpp"
#include "PostureBarUI.hpp"
#include "Memory.hpp"

namespace ER 
{
    // FD4 singleton lookup by class name, after the from-singleton crate (crates.io, 3.0.1,
    // src/find.rs, MIT/Apache-2.0). The game guards each singleton with
    //   mov reg,[rip+instance]; test reg,reg; jne ok; lea rcx,[rip+reflection]; call get_name;
    //   then mov edx,imm / lea r8 / lea rcx / mov r9,rax in some order, and a call that reports it.
    // get_name(reflection) returns the class name once the game has set up its reflection data,
    // so the lookup works on any game version but only after startup.
    struct Fd4Site
    {
        uintptr_t instance;
        uintptr_t reflection;
    };
    using Fd4GetName = const char* (*)(const void*);

    static bool isRexW(uint8_t b) { return (b & 0xF8) == 0x48; }

    static const uint8_t* fd4CondJump(const uint8_t* p)
    {
        if (p[-2] == 0x75)
            return p - 2;
        if (p[-6] == 0x0F && p[-5] == 0x85)
            return p - 6;
        return nullptr;
    }

    // Start of the `mov reg,[rip+x]` that feeds the `test reg,reg; jne` ending at p, or null.
    static const uint8_t* fd4TestMov(const uint8_t* p)
    {
        auto j = fd4CondJump(p);
        if (!j)
            return nullptr;
        auto t = j - 3;
        if (!isRexW(t[0]) || t[1] != 0x85 || (t[2] & 0xC0) != 0xC0 || (t[2] & 7) != ((t[2] >> 3) & 7))
            return nullptr;
        for (int pad = 0; pad <= 3; ++pad)
        {
            auto m = t - 7 - pad;
            if (isRexW(m[0]) && m[1] == 0x8B && (m[2] & 0xC7) == 5 && ((m[2] >> 3) & 7) == (t[2] & 7)
                && ((m[0] >> 2) & 1) == (t[0] & 1))
                return m;
        }
        return nullptr;
    }

    static uintptr_t ripTarget(const uint8_t* insn, size_t len)
    {
        return (uintptr_t)(insn + len) + *(const int32_t*)(insn + len - 4);
    }

    static std::vector<Fd4Site> g_Fd4Sites;
    static Fd4GetName g_Fd4GetName = nullptr;

    static void scanFd4Sites()
    {
        Module mod(nullptr);
        auto base = mod.Base().As<uintptr_t>();
        auto nt = mod.GetNtHeaders();
        auto sec = IMAGE_FIRST_SECTION(nt);
        const uint8_t* text = nullptr;
        size_t textLen = 0;
        uintptr_t dataLo = 0, dataHi = 0;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (!text && memcmp(sec[i].Name, ".text\0\0", 8) == 0)
            {
                text = (const uint8_t*)(base + sec[i].VirtualAddress);
                textLen = sec[i].Misc.VirtualSize;
            }
            else if (!dataLo && memcmp(sec[i].Name, ".data\0\0", 8) == 0)
            {
                dataLo = base + sec[i].VirtualAddress;
                dataHi = dataLo + sec[i].Misc.VirtualSize;
            }
        }
        if (!text || !dataLo)
            return;

        const uint8_t* end = text + textLen;
        for (const uint8_t* p = text + 0x40; p + 0x20 < end; ++p)
        {
            if (*p != 0xBA)
                continue;
            // Collect up to 4 instructions around `mov edx,imm32`: lea rcx / lea r8 / lea r9 / mov r9,rax.
            const uint8_t* first = p;
            int n = 1, mask = 0;
            const uint8_t* next = p + 5;
            bool ok = true;
            while (n < 4)
            {
                if (next[0] == 0x48 && next[1] == 0x8D && next[2] == 0x0D) { mask |= 1; next += 7; }
                else if (next[0] == 0x4C && next[1] == 0x8D && next[2] == 0x05) { mask |= 2; next += 7; }
                else if (next[0] == 0x4C && next[1] == 0x8D && next[2] == 0x0D) { mask |= 4; next += 7; }
                else if (next[0] == 0x4C && next[1] == 0x8B && next[2] == 0xC8) { mask |= 8; next += 3; }
                else if (next[0] == 0xE8) break;
                else { ok = false; break; }
                ++n;
            }
            while (ok && n < 4)
            {
                auto q = first - 7;
                if (q < text) { ok = false; break; }
                if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x0D) { mask |= 1; first = q; }
                else if (q[0] == 0x4C && q[1] == 0x8D && q[2] == 0x05) { mask |= 2; first = q; }
                else if (q[0] == 0x4C && q[1] == 0x8D && q[2] == 0x0D) { mask |= 4; first = q; }
                else if (q[4] == 0x4C && q[5] == 0x8B && q[6] == 0xC8) { mask |= 8; first = q + 4; }
                else { ok = false; break; }
                ++n;
            }
            if (!ok || n != 4 || mask != 11)
                continue;
            for (int pad = 0; pad <= 1; ++pad)
            {
                auto call = first - 5 - pad;
                if (call[0] != 0xE8)
                    continue;
                auto lea = call - 7;
                if (!(lea[0] == 0x48 && lea[1] == 0x8D && lea[2] == 0x0D))
                    continue;
                auto mov = fd4TestMov(lea);
                if (!mov)
                    continue;
                auto inst = ripTarget(mov, 7);
                if (inst < dataLo || inst >= dataHi || (inst & 7))
                    break;
                if (!g_Fd4GetName)
                {
                    auto fn = ripTarget(call, 5);
                    if (fn < (uintptr_t)text || fn >= (uintptr_t)end)
                        break;
                    g_Fd4GetName = (Fd4GetName)fn;
                }
                g_Fd4Sites.push_back({ inst, ripTarget(lea, 7) });
                break;
            }
        }
    }

    // get_name can fault before the game's reflection data exists; keep SEH apart from C++ objects.
    static bool fd4NameIs(Fd4GetName fn, uintptr_t reflection, const char* name)
    {
        __try
        {
            auto s = fn((const void*)reflection);
            return s && strcmp(s, name) == 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    static uintptr_t findSingletonStatic(const char* name)
    {
        if (!g_Fd4GetName)
            return 0;
        for (auto& s : g_Fd4Sites)
            if (fd4NameIs(g_Fd4GetName, s.reflection, name))
                return s.instance;
        return 0;
    }

    void Hooking::findMenuMan()
    {
        auto exe = Module(nullptr).Base().As<uintptr_t>();
        char buf[160];
        if (g_Fd4Sites.empty())
        {
            scanFd4Sites();
            snprintf(buf, sizeof buf, "FD4 singleton sites %zu, get_name rva %llX", g_Fd4Sites.size(),
                g_Fd4GetName ? (unsigned long long)((uintptr_t)g_Fd4GetName - exe) : 0ull);
            Logger::log(buf);
        }
        if (csMenuManStatic = findSingletonStatic("CSMenuMan"); csMenuManStatic)
        {
            snprintf(buf, sizeof buf, "CSMenuMan static rva %llX", (unsigned long long)(csMenuManStatic - exe));
            Logger::log(buf);
        }
        else
            Logger::log("CSMenuMan not found yet", LogLevel::Error);
    }
    Hooking::Hooking()
    {
        MH_Initialize();
    }

    Hooking::~Hooking()
    {
        MH_RemoveHook(MH_ALL_HOOKS);
    }

    void Hooking::Hook()
    {
#ifdef DEBUGLOG
        try
        {
#endif // DEBUGLOG
            Logger::log("Start Hooking");

            Logger::log("Hooking Elden Ring methods");

            Logger::log("Looking for worldChr signature");
            if (worldChrSignature = Signature("48 8B 05 ? ? ? ? 48 85 C0 74 0F 48 39 88").Scan().Add(3).Rip().As<uint64_t>(); !worldChrSignature)
                Logger::log("Failed to find worldChr signature", LogLevel::Error);

            Logger::log("Looking for CSFeMan signature");
            if (CSFeManSignature = Signature("48 8B 0D ? ? ? ? 8B DA 48 85 C9 75 ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B C8 4C 8D 05 ? ? ? ? BA B4 00 00 00 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 8B D3 E8 ? ? ? ? 48 8B D8").Scan().Add(3).Rip().As<uint64_t>(); !CSFeManSignature)
                Logger::log("Failed to find worldChr signature", LogLevel::Error);

            Logger::log("Looking for CSMenuMan");
            findMenuMan();
            Logger::log("Looking for GetChrInsFromHandleFunc signature");
            if (GetChrInsFromHandleFunc = (GetChrInsFromHandle)Signature("48 83 EC 28 E8 17 FF FF FF 48 85 C0 74 08 48 8B 00 48 83 C4 28 C3").Scan().As<uint64_t>(); !GetChrInsFromHandleFunc)
                Logger::log("Failed to find GetChrInsFromHandleFunc signature", LogLevel::Error);

            Logger::log("Looking for UpdateUIBarStructsFunc signature");
            if (UpdateUIBarStructsFunc = (UpdateUIBarStructs)Signature("40 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 60 48 C7 44 24 30 FE FF FF FF 48 89 9C 24 B0 00 00 00 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 58 48").Scan().As<uint64_t>(); !UpdateUIBarStructsFunc)
                Logger::log("Failed to find UpdateUIBarStructsFunc signature", LogLevel::Error);

            Logger::log("Hooking UpdateUIBarStructsFunc");
            if (MH_CreateHook(UpdateUIBarStructsFunc, &g_postureUI->updateUIBarStructs, (void**)&g_postureUI->updateUIBarStructsOriginal) != MH_STATUS::MH_OK)
                Logger::log("Failed to hook UpdateUIBarStructsFunc", LogLevel::Error);

            Logger::log("Hooking DirectX methods");

            g_D3DRenderer->Hook();

            MH_EnableHook(MH_ALL_HOOKS);
#ifdef DEBUGLOG
        }
        catch (const std::exception& e)
        {
            Logger::useLogger = true;
            Logger::log(e.what(), LogLevel::Error);
            throw;
        }
        catch (...)
        {
            Logger::useLogger = true;
            Logger::log("Unknown exception during Hooking::Hook", LogLevel::Error);
            throw;
        }
#endif // DEBUGLOG
    }

    void Hooking::Unhook()
    {
        g_D3DRenderer->Unhook();
        MH_RemoveHook(MH_ALL_HOOKS);
    }
}