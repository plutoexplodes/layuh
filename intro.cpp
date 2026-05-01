#include <iostream>
#include "util/classes/classes.h"
#include <string>
#include <Windows.h>
#include "util/protection/hider.h"
// VMProtect removed
#include "util/protection/hashes/hash.h"
#include <conio.h>

#include <iostream>
#include <string>
#include <thread>
#include <filesystem>
#include <Windows.h>
#include <fstream>
#include <limits>
#include <cstdio>
#include <algorithm>
#include <chrono>
#include <ios>
#include "util/protection/keyauth/auth.hpp"
#include "util/protection/keyauth/json.hpp"
#include <iostream>
#include <string>
#include <map>
#include <random>
#include <Windows.h>
#include "util/globals.h"
#include "features/wallcheck/wallcheck.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <intrin.h>
#include <chrono>
#include <ctime>
#include "util/console/console.h"
//#include "protect/prot.hxx"
#pragma comment(lib, "urlmon.lib")

static bool injected = false;
static bool running = true;

bool robloxRunning = false;

namespace fs = std::filesystem;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
// line 719 contains auth

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
void enableANSIColors();

static bool g_authSuccess = false;
static std::string g_sessionToken = ("");
static std::chrono::steady_clock::time_point g_lastCheck;
static std::atomic<bool> g_securityThreadActive{ false };
static std::atomic<bool> g_authValidated{ false };


const std::string compilation_date = (__DATE__);
const std::string compilation_time = (__TIME__);

#pragma code_seg((".layuh"))


using namespace KeyAuth;
// https://keyauth.cc/
std::string getDecryptedName() {




    std::string ed = ("Trey26653's Application");

    return ed;

}

std::string getDecryptedOwnerID() {




    std::string ed = ("l8marLfsFo");

    return ed;

}

std::string getDecryptedVersion() {




    std::string ed = ("1.0");

    return ed;

}

std::string getDecryptedURL() {




    std::string ed = ("https://keyauth.win/api/1.3/");

    return ed;

}



class SecureKeyAuth {
private:
    std::unique_ptr<KeyAuth::api> m_keyauth;
    std::string m_lastResponse;
    std::chrono::steady_clock::time_point m_lastValidation;
    uint32_t m_instanceMagic = 0xABCDEF00;

public:
    SecureKeyAuth() {




        try {
            //std::string createMsg = (("[DEBUG] Creating SecureKeyAuth instance"));
          //  std::cout << createMsg << std::endl;
           // std::cout << (createMsg);


            //std::string secPassMsg = (("[DEBUG] Security validation passed in constructor"));
            //std::cout << secPassMsg << std::endl;
            //std::cout << (secPassMsg);

            std::string path = ("");


            m_keyauth = std::make_unique<KeyAuth::api>(
                getDecryptedName(),
                getDecryptedOwnerID(),
                getDecryptedVersion(),
                getDecryptedURL(),
                path
            );

            //std::string completeMsg = (("[DEBUG] SecureKeyAuth constructor completed successfully"));
            //std::cout << completeMsg << std::endl;
            //std::cout << (completeMsg);


        }
        catch (const std::exception& e) {
            //std::string exceptionMsg = (("[DEBUG] Exception in SecureKeyAuth constructor: "));
            //std::cout << exceptionMsg << e.what() << std::endl;
            //std::cout << (exceptionMsg);
            exit(0xDEADBEEF);
        }
        catch (...) {
            //std::string unknownMsg = (("[DEBUG] Unknown exception in SecureKeyAuth constructor"));
            //std::cout << unknownMsg << std::endl;
            //std::cout << (unknownMsg);
            exit(0xDEADBEEF);
        }

    }

    __forceinline bool initialize() {




        try {

            m_keyauth->init();


            if (!m_keyauth->response.success) {

                return false;
            }

            m_lastValidation = std::chrono::steady_clock::now();


            return true;

        }
        catch (const std::exception& e) {

            return false;
        }
        catch (...) {

            return false;
        }

    }

    __forceinline bool authenticateUser() {


        std::string appDataPath = std::getenv(("APPDATA"));
        std::string authFilePath = appDataPath + ("\\Layuh\\auth.bin");

        if (std::filesystem::exists(authFilePath)) {
            std::ifstream authFile(authFilePath);
            std::string username, password;
            if (std::getline(authFile, username) && std::getline(authFile, password)) {
                m_keyauth->login(username, password);
                if (m_keyauth->response.success) {
                    return true;
                }
            }
            authFile.close();
        }

        system("cls");

        std::string authHeader = ("--------Layuh Authentication --------");
        std::string option1 = ("\n[1] Login");
        std::string option2 = ("\n[2] Register");
        std::string chooseMsg = ("\n\n Choose option: ");

        std::cout << authHeader << option1 << option2 << chooseMsg;

        int option;
        std::cin >> option;
        std::cin.ignore();

        switch (option) {
        case 1: {
            std::string username, password, licensekey;
            std::cout << ("\n Username: ");
            std::getline(std::cin, username);
            std::cout << (" Password: ");
            std::getline(std::cin, password);

            m_keyauth->login(username, password);
            if (m_keyauth->response.success) {
                std::filesystem::create_directories(appDataPath + "\\Layuh");
                std::ofstream authFile(authFilePath);
                authFile << username << "\n" << password;
                authFile.close();
                return true;
            }
            else {
                std::cout << ("\n Login failed: ") << m_keyauth->response.message << std::endl;
                Sleep(2000);
                return false;
            }
        }
        case 2: {
            std::string username1, password2, licensekey3;
            std::cout << ("\n Username: ");
            std::getline(std::cin, username1);
            std::cout << (" Password: ");
            std::getline(std::cin, password2);
            std::cout << (" License Key: ");
            std::getline(std::cin, licensekey3);

            m_keyauth->regstr(username1, password2, licensekey3);
            if (m_keyauth->response.success) {
                std::filesystem::create_directories(appDataPath + "\\Layuh");
                std::ofstream authFile(authFilePath);
                authFile << username1 << "\n" << password2;
                authFile.close();
                return true;
            }
            else {
                std::cout << ("\n Register failed: ") << m_keyauth->response.message << std::endl;
                Sleep(2000);
                return false;
            }
        }

        default:
            std::cout << ("\n Invalid option") << std::endl;
            Sleep(1500);
            return false;
        }
    }

    __forceinline bool isSubActive() const {
        if (!m_keyauth) return false;
    }


    __forceinline bool validateSession() {






        auto now = std::chrono::steady_clock::now();
        auto timeSinceCheck = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastValidation).count();

        if (timeSinceCheck > 30) {
            m_keyauth->check();

            if (!m_keyauth->response.success) {
                return false;
            }

            m_lastValidation = now;

        }

        return true;

    }

    __forceinline std::string getUsername() const {


        return m_keyauth->user_data.username;

    }

    __forceinline std::vector<std::string> getSubscriptions() const {



        std::vector<std::string> subs;
        for (const auto& sub : m_keyauth->user_data.subscriptions) {
            subs.push_back(sub.name);
        }

        return subs;

    }

    __forceinline bool hasSubscription(const std::string& subName) const {




        for (const auto& sub : m_keyauth->user_data.subscriptions) {
            if (sub.name == subName) {

                return true;
            }
        }
        return false;

    }

private:
    __forceinline bool performLogin() {




        try {
            std::string username, password;

            std::string userPrompt = (("\n Username: "));
            std::string passPrompt = ((" Password: "));

            std::cout << userPrompt;
            // std::cout << (userPrompt);
            std::cin >> username;

            std::cout << passPrompt;
            // std::cout << (passPrompt);
            std::cin >> password;

            if (username.empty() || password.empty()) {
                std::string emptyMsg = (("\n Username and password cannot be empty"));
                std::cout << emptyMsg << std::endl;
                std::cout << (emptyMsg);
                Sleep(2000);
                return false;
            }



            m_keyauth->login(username, password);

            if (!m_keyauth->response.success) {
                std::string failMsg = (("\n Login failed: "));
                std::cout << failMsg << m_keyauth->response.message << std::endl;
                std::cout << (failMsg);
                Sleep(2000);
                return false;
            }
            // printf("passed")
            // printf(m_keyauth->response.success);
            // system("pause");

            g_authSuccess = true;
            g_authValidated = true;
            // g_sessionToken = "lol__" + ("_") + std::to_string(GetTickCount64());
            globals::instances::username = ("LayuhUser");
            return true;
        }
        catch (const std::exception& e) {
            std::string exceptionMsg = (("Login exception: "));
            std::cout << exceptionMsg << e.what() << std::endl;
            std::cout << (exceptionMsg);
            Sleep(2000);
            return false;
        }
        catch (...) {
            std::string unknownMsg = (("Unknown login error"));
            std::cout << unknownMsg << std::endl;
            std::cout << (unknownMsg);
            Sleep(2000);
            return false;
        }

    }

};

static std::unique_ptr<SecureKeyAuth> g_secureAuth = nullptr;


void enableANSIColors() {



    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
        SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

}

std::string tm_to_readable_time(tm ctx) {


    char buffer[80];
    strftime(buffer, sizeof(buffer), (("%a %m/%d/%y %H:%M:%S %Z")), &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {



    auto cv = strtol(timestamp.c_str(), NULL, 10);

    return (time_t)cv;

}

static std::tm timet_to_tm(time_t timestamp) {



    std::tm context;
    localtime_s(&context, &timestamp);

    return context;

}



bool performAuthentication() {

    g_secureAuth = std::make_unique<SecureKeyAuth>();

    if (!g_secureAuth->initialize()) {

        Sleep(3000);
        return false;
    }



    if (g_secureAuth->authenticateUser()) {
        // printf("validated");
        // system("pause");
        return true;
    }


    Sleep(2000);
    return false;


}
void Antidll()
{
    //for (int i = (0); i < (200); ++i) { NoStepie(); }
    PROCESS_MITIGATION_ASLR_POLICY policyInfo;
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY PMCFGP{};
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY PMBSP{};
    PROCESS_MITIGATION_DEP_POLICY PMDP{};
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY PMILP{};
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = { (0) };
    PROCESS_MITIGATION_FONT_DISABLE_POLICY fontDisablePolicy = { (0) };
    policyInfo.EnableBottomUpRandomization = (1);
    policyInfo.EnableForceRelocateImages = (1);
    policyInfo.EnableHighEntropy = (1);
    policyInfo.DisallowStrippedImages = (0);
    PMCFGP.EnableControlFlowGuard = (1);
    PMBSP.MicrosoftSignedOnly = (1);
    PMCFGP.StrictMode = (1);
    PMDP.Permanent = (1);
    PMDP.Enable = (1);
    PMILP.PreferSystem32Images = (1);
    PMILP.NoRemoteImages = (1);
    PMILP.NoLowMandatoryLabelImages = (1);
    handlePolicy.RaiseExceptionOnInvalidHandleReference = (1);
    handlePolicy.HandleExceptionsPermanentlyEnabled = (1);
    fontDisablePolicy.DisableNonSystemFonts = (1);
    SetProcessMitigationPolicy(ProcessASLRPolicy, &policyInfo, sizeof(policyInfo));
    SetProcessMitigationPolicy(ProcessSignaturePolicy, &PMBSP, sizeof(PMBSP));
    SetProcessMitigationPolicy(ProcessImageLoadPolicy, &PMILP, sizeof(PMILP));
}
void textbolgesinikoruma() {
    HMODULE hmod = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)hmod;
    PIMAGE_NT_HEADERS ntheader = (PIMAGE_NT_HEADERS)((BYTE*)hmod + dosheader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionheader = IMAGE_FIRST_SECTION(ntheader);

    void* textaddr = nullptr;
    void* primyokaddr = nullptr;
    size_t textsize = 0;
    size_t primyoksize = 0;

    for (int i = 0; i < ntheader->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionheader[i].Name, ".text") == 0) {
            textaddr = (void*)((BYTE*)hmod + sectionheader[i].VirtualAddress);
            textsize = sectionheader[i].Misc.VirtualSize;
        }
        if (strcmp((char*)sectionheader[i].Name, (".layuh")) == 0) {
            primyokaddr = (void*)((BYTE*)hmod + sectionheader[i].VirtualAddress);
            primyoksize = sectionheader[i].Misc.VirtualSize;
        }
    }

    if (textaddr && primyokaddr && textsize > 0) {
        DWORD oldprotect;
        VirtualProtect(textaddr, textsize, PAGE_EXECUTE_READWRITE, &oldprotect);

        size_t copysize = (textsize < primyoksize) ? textsize : primyoksize;
        unsigned char* textptr = static_cast<unsigned char*>(textaddr);

        for (size_t i = 0; i < copysize; ++i) {
            textptr[i] = 0x00;
        }

        VirtualProtect(textaddr, textsize, PAGE_NOACCESS, &oldprotect);
    }
}

struct bellekkorumasistem {
    static void primyokbolgesinikarma() {
        HMODULE hmod = GetModuleHandle(NULL);
        PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)hmod;
        PIMAGE_NT_HEADERS ntheader = (PIMAGE_NT_HEADERS)((BYTE*)hmod + dosheader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionheader = IMAGE_FIRST_SECTION(ntheader);

        for (int i = 0; i < ntheader->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)sectionheader[i].Name, (".layuh")) == 0) {
                DWORD oldprotect;
                void* sectionaddr = (void*)((BYTE*)hmod + sectionheader[i].VirtualAddress);
                VirtualProtect(sectionaddr, sectionheader[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);

                unsigned char* ptr = static_cast<unsigned char*>(sectionaddr);
                for (size_t j = 0; j < sectionheader[i].Misc.VirtualSize; ++j) {
                    ptr[j] ^= (0xAA ^ (j & 0xFF));
                }

                VirtualProtect(sectionaddr, sectionheader[i].Misc.VirtualSize, PAGE_EXECUTE_READ, &oldprotect);
                break;
            }
        }
    }
};
__forceinline BOOL CALLBACK Layuh_module(HWND hwnd, LPARAM lParam)
{

    std::vector<std::string> windowTitles = {
        "hacker", "Resource Monitor", ") Properties", "dexz", "re-kit", "byte2mov",
        "Cheat Engine", "Command Prompt", "pssuspend", "sysinternals.com", "HttpDebuggerPro", "HTTP Debugger"
    };

    std::vector<std::string> windowClassNames = {
        ("ProcessHacker"), ("Qt5QWindowIcon"), "WindowsForms10.Window.8.app.0.378734a",
        "MainWindowClassName", "BrocessRacker", ("Http Debugger"), ("HttpDebuggerPro"), ("XTPMainFrame"),
    };

    DWORD processId;
    char wndTitle[256] = { 0 };
    char wndClassName[256] = { 0 };

    GetWindowThreadProcessId(hwnd, &processId);
    DWORD currentProcessId = GetCurrentProcessId();

    GetWindowTextA(hwnd, wndTitle, sizeof(wndTitle));
    GetClassNameA(hwnd, wndClassName, sizeof(wndClassName));

    std::string windowTitle(wndTitle);
    std::string windowClassName(wndClassName);

    for (const auto& title : windowTitles) {
        if (windowTitle.find(title) != std::string::npos)
        {
            if (windowTitle == ("re-kit") || windowTitle == ("byte2mov"))
            {
                // Custom flag or attack handler removed
            }

            SendMessageA(hwnd, WM_CLOSE, 0, 0);
            return TRUE;
        }
    }

    for (const auto& className : windowClassNames)
    {
        if (windowClassName.find(className) != std::string::npos)
        {
            if (processId != currentProcessId)
            {
                SendMessageA(hwnd, WM_CLOSE, 0, 0);
                return TRUE;
            }
        }
    }

    return TRUE;

}
__forceinline void babayim() {

    while (true) {
        EnumWindows(Layuh_module, 0);
        Sleep(5);
    }

}


__forceinline int weinit() {


    std::thread(babayim).detach();
    //Antidll();

    enableANSIColors();
    HWND hwnd = GetConsoleWindow();
    SetWindowText(hwnd, (("Layuh")));
    
    // Console styling: smaller font, transparent background, red text
    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof(cfi);
    cfi.nFont = 0;
    cfi.dwFontSize.X = 0;
    cfi.dwFontSize.Y = 12; // Smaller font size
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy_s(cfi.FaceName, L"Consolas");
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);
    
    // Set console colors to red text on transparent background
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);
    
    // Make console window transparent
    SetWindowLong(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd, 0, 200, LWA_ALPHA); // 200/255 transparency
    
    std::string mainInitMsg = (("[DEBUG] Main initialization starting\n"));
    std::cout << (mainInitMsg);
    
    std::string consoleSetupMsg = (("[DEBUG] Console setup complete"));
    std::cout << (consoleSetupMsg);
    if (!performAuthentication()) {
        exit(0xAU);
    }
    // printf("works\n");
    // system("pause");


    ShowWindow(hwnd, SW_HIDE);
    tray::initialize();
    engine::startup();

    //
    return 0;


}
#define secure __forceinline
#pragma code_seg()

int baslatici = weinit();

int main()
{
    std::string weinitfakenigger = "Initializing....";
    std::string weinitamnbbibiibbibibibi = "[1] Login";
    return FLT_MAX;

    //hashes();

    //return 0;

}