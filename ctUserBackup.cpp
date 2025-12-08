#include <windows.h>
#include <iostream>
#include <regex>
#include <vector>
#include <string>
#include <cstdio>
#include <cinttypes>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <thread> 
#include <algorithm>
#include <Shlobj.h>

extern "C" int __cdecl wuprintf(const wchar_t* fmt,...){
    // super-basic fallback: just forward to vfwprintf(stdout, ...)
    va_list ap;
    va_start(ap,fmt);
    int r=vfwprintf(stdout,fmt,ap);
    va_end(ap);
    return r;
}


extern "C" {
    // If you have cdio headers available, include them.
    // Otherwise, keep the minimal forward decls below.
#if __has_include(<cdio/cdio.h>)
#  include <cdio/cdio.h>
#else
    struct CdIo;            // opaque type
    typedef CdIo CdIo_t;
    typedef int driver_id_t;
#endif
}

// Provide no-op stubs (same signatures)
extern "C" {
    CdIo_t* cdio_open(const char* /*psz_source*/,driver_id_t /*driver_id*/){
        return nullptr;
    }
    void cdio_destroy(CdIo_t* /*p_cdio*/){
        // no-op
    }
}

extern "C" {
#include "wimlib.h"
#pragma comment(lib, "wimlib.lib")
#pragma comment(lib, "libcdio-udf.lib")
#pragma comment(lib, "libcdio-iso9660.lib")
#pragma comment(lib, "libcdio-driver.lib")

//#include ""
//#ifdef _DEBUG
//#include "devel/wimlib.h"
//#else
//#include "wimlib.h"
//#endif
}


#ifndef _DEBUG
//#pragma comment(lib, "libs/static_x86_64/libwim.lib")
//#pragma comment(lib,"libmingwex.a")
//#pragma comment(lib,"libmingw32.a")
//#pragma comment(lib,"libmsvcrt.a")
//#pragma comment(lib,"libclang_rt.builtins-x86_64.a")
#endif

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "ntdll.lib")


// --- Global C++ Variables ---
static FILE* imagex_info_file;

std::vector<std::wstring> g_aSysFrags={
    L"\\\\Windows\\\\System32\\\\Microsoft\\\\Protect",
    L"\\\\Windows\\\\System32\\\\Config",
    L"\\\\Windows\\\\System32\\\\Config\\\\SystemProfile",
    L"\\\\Windows\\\\ServiceProfiles\\\\LocalService",
    L"\\\\Windows\\\\ServiceProfiles\\\\NetworkService",
    L"\\\\ProgramData\\\\Microsoft\\\\Crypto",
    L"\\\\ProgramData\\\\Microsoft\\\\Vault",
    L"\\\\ProgramData\\\\Microsoft\\\\Wlansvc",
    L"\\\\ProgramData\\\\Microsoft\\\\Wwansvc"
};

std::vector<std::wstring> g_aUserFrags={
    L"\\\\CrashDumps",
    L"\\\\DataSharing",
    L"\\\\IsolatedStorage",
    L"\\\\ConnectedDevicesPlatform",
    L"\\\\Microsoft\\\\NGC",
    L"\\\\Microsoft\\\\Vault",
    L"\\\\Microsoft\\\\Crypto",
    L"\\\\Microsoft\\\\Protect",
    L"\\\\Microsoft\\\\Credentials",
    L"\\\\Microsoft\\\\SystemCertificates",
    L"\\\\Microsoft\\\\Windows\\\\CloudStore",
    L"\\\\Microsoft\\\\Windows\\\\CloudAPCache",
    L"\\\\Microsoft\\\\CryptnetUrlCache"
};

std::vector<std::wstring> g_aChromeLocs={
    L"\\\\Microsoft\\\\Edge\\\\User Data",
    L"\\\\Microsoft\\\\Edge SxS\\\\User Data",
    L"\\\\Google\\\\Chrome\\\\User Data",
    L"\\\\Google\\\\Chrome SxS\\\\User Data",
    L"\\\\Google\\\\Chromium\\\\User Data",
    L"\\\\Google\\\\CocCoc\\\\User Data",
    L"\\\\Google\\\\Comodo\\\\Dragon\\\\User Data",
    L"\\\\Google\\\\Elements Browser\\\\User Data",
    L"\\\\Google\\\\Epic Privacy\\\\Browser\\\\User Data",
    L"\\\\7Star\\\\7Star\\\\User Data",
    L"\\\\Amigo\\\\User Data",
    L"\\\\BraveSoftware\\\\Brave-Browser\\\\User Data",
    L"\\\\CentBrowser\\\\User Data",
    L"\\\\Chedot\\\\User Data",
    L"\\\\Kometa\\\\User Data",
    L"\\\\Opera Software\\\\Opera Stable",
    L"\\\\Orbitum\\\\User Data",
    L"\\\\Sputnik\\\\User Data",
    L"\\\\Torch\\\\User Data",
    L"\\\\Uran\\\\User Data",
    L"\\\\Vivaldi\\\\User Data",
    L"\\\\Yandex\\\\YandexBrowser\\\\User Data",
    L"\\\\UCBrowser"
};

std::vector<std::wstring> g_aChromeFrags={
    L"\\\\Cookies",
    L"\\\\Bookmarks",
    L"\\\\History",
    L"\\\\AutoFill",
    L"\\\\IndexedDB",
    L"\\\\Extension Cookies",
    L"\\\\Login Data",
    L"\\\\Safe Browsing Network\\\\Safe Browsing Cookies",
    L"\\\\Network\\\\Cookies"
};

std::vector<std::wstring> g_aExclFlt={
    L"\\\\SendTo\\\\",
    L"\\\\Recent\\\\",
    L"\\\\Edge Designer\\\\",
    L"\\\\Edge Kids Mode\\\\",
    L"\\\\Edge Shopping\\\\",
    L"\\\\Edge Tipping\\\\",
    L"\\\\Edge Travel\\\\",
    L"\\\\Edge Wallet\\\\",
    L"\\\\Windows\\\\WinX\\\\",
    L"\\\\Libraries\\\\",
    L"\\\\D3DSCache\\\\",
    L"\\\\Feeds Cache\\\\",
    L"\\\\CacheStorage\\\\",
    L"\\\\Feeds\\\\",
    L"\\\\ShaderCache\\\\",
    L"\\\\User Data\\\\Snapshots\\\\",
    L"\\\\Service Worker\\\\CacheStorage\\\\",
    L"\\\\Service Worker\\\\ScriptCache\\\\",
    L"\\\\Microsoft\\\\Templates\\\\",
    L"\\\\fontconfig\\\\cache\\\\",
    L"\\\\Code Cache\\\\",
    L"\\\\Cache\\\\Cache_Data\\\\",
    L"\\\\LocalLow\\\\Adobe\\\\",
    L"\\\\Links\\\\",
    L"\\\\Microsoft\\\\Office\\\\",
    L"\\\\PowerToys\\\\",
    L"\\\\Teams\\\\",
    L"\\\\RoamCache\\\\",
    L"\\\\pip\\\\cache\\\\",
    L"\\\\Package Cache\\\\",
    L"\\\\Microsoft\\\\Packages\\\\",
    L"\\\\Terminal Server Client\\\\",
    L"\\\\TokenBroker\\\\Cache\\\\",
    L"\\\\ActionCenterCache\\\\",
    L"\\\\Local\\\\Programs\\\\",
    L"\\\\Local\\\\Temp\\\\",
    L"\\\\Roaming\\\\Code\\\\",
    L"\\\\Microsoft\\\\Installer\\\\",
    L"\\\\AppCenterCache\\\\",
    L"\\\\Burn\\\\",
    L"\\\\Windows\\\\Caches\\\\",
    L"\\\\TeamsMeetingAddin\\\\",
    L"\\\\TeamsPresenceAddin\\\\",
    L"\\\\thumbcache\\\\",
    L"\\\\WebCache\\\\",
    L"\\\\GPUCache\\\\",
    L"\\\\pyppeteer\\\\",
    L"\\\\iconcache\\\\",
    L"\\\\IntelGraphicsProfiles\\\\",
    L"IconCache\\.db$",
    L"bing\\.url$",
    L"desktop\\.ini$",
    L"\\.igpi$"
};

//std::vector<std::wregex> g_reSysFrags;
//std::vector<std::wregex> g_reUserFrags;
//std::vector<std::wregex> g_reChromeLocs;
//std::vector<std::wregex> g_reChromeFrags;
std::vector<std::wregex> g_reExclFlt;

//std::wregex g_reExclFlt;


// --- Function Prototypes ---
std::wstring GetAppVersionString(const std::wstring& value_name);
void CompileRegexPatterns(const std::vector<std::wstring>& strPat,std::vector<std::wregex>& aRegEx);
bool CreateBackupWim(const std::wstring& sourceDirectory,const std::wstring& backupName);
static enum wimlib_progress_status __cdecl MyProgressCallback(enum wimlib_progress_msg msg,union wimlib_progress_info* info,void* user_context);
std::wstring GenerateTimestampedName(const std::wstring& backupName);
std::wstring GetUserProfileDirectory();
static void report_scan_progress(const wimlib_progress_info::wimlib_progress_info_scan* scan,bool done);
static unsigned get_unit(uint64_t total_bytes,const wchar_t** name_ret);
void CompileSingleRegex(const std::vector<std::wstring>& strPat,std::wregex& re);

// --- Main Entry Point ---
int wmain(int argc,wchar_t* argv[]){
    const std::wstring g_sAlias=L"ctUserBackup";
    const std::wstring g_sVersion=GetAppVersionString(L"ProductVersion");
    const std::wstring g_sTitle=g_sAlias+L" v"+(g_sVersion.empty()?L"?.?.?.?":g_sVersion);
    
    std::wcout<<g_sTitle<<std::endl;

    imagex_info_file=stdout;
    wimlib_set_print_errors(true);
    if(wimlib_global_init(0)!=0){
        std::wcerr<<L"Failed to initialize wimlib!"<<std::endl;
        return 1;
    }

    CompileRegexPatterns(g_aExclFlt,g_reExclFlt);
    //CompileSingleRegex(g_aExclFlt,g_reExclFlt);

    std::wstring sourceToBackup;
    std::wstring nameOfBackup;
    if(argc<2){
        sourceToBackup=GetUserProfileDirectory();
        if(sourceToBackup.empty()){
            fwprintf(stderr,L"ERROR: Could not determine user profile directory.\n");
            wimlib_global_cleanup();
            return 1;
        }
    } else{
        sourceToBackup=argv[1];
    }
    nameOfBackup=std::filesystem::path(sourceToBackup).filename().wstring();
    if(nameOfBackup.empty()||nameOfBackup==L"."||nameOfBackup==L".."){
        nameOfBackup=L"Backup"; // Fallback name
    }

    std::wcout<<L"\nStarting backup..."<<std::endl;
    if(CreateBackupWim(sourceToBackup,nameOfBackup)){
        std::wcout<<L"\nBackup completed successfully."<<std::endl;
    } else{
        std::wcerr<<L"\nBackup failed."<<std::endl;
    }
    wimlib_global_cleanup();
    return 0;
}



bool CreateBackupWim(const std::wstring& sourceDirectory,const std::wstring& backupName){
    WIMStruct* wim=nullptr;
    int ret=0;

    std::wstring imageName=GenerateTimestampedName(backupName);
    std::wstring wimFile=backupName+L".wim";

    bool appending=std::filesystem::exists(wimFile);
    int add_flags=WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE|WIMLIB_ADD_FLAG_WINCONFIG|
        WIMLIB_ADD_FLAG_VERBOSE|WIMLIB_ADD_FLAG_FILE_PATHS_UNNEEDED|
        WIMLIB_ADD_FLAG_TEST_FILE_EXCLUSION|WIMLIB_ADD_FLAG_NO_ACLS|
        WIMLIB_ADD_FLAG_SNAPSHOT;
    int write_flags=WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
    int open_flags=0;//WIMLIB_OPEN_FLAG_WRITE_ACCESS;

    unsigned num_threads=max(1u,std::thread::hardware_concurrency()/2);

    if(appending){
        write_flags|=WIMLIB_WRITE_FLAG_REBUILD;
        open_flags|=WIMLIB_OPEN_FLAG_CHECK_INTEGRITY;
        ret=wimlib_open_wim_with_progress(wimFile.c_str(),open_flags|WIMLIB_OPEN_FLAG_WRITE_ACCESS,&wim,MyProgressCallback,nullptr);
    } else{
        ret=wimlib_create_new_wim(WIMLIB_COMPRESSION_TYPE_LZX,&wim);
        wimlib_register_progress_function(wim,MyProgressCallback,nullptr);
    }

    if(ret!=0){
        fwprintf(stderr,L"ERROR: Failed to open or create WIM structure: %ls\n",wimlib_get_error_string(static_cast<wimlib_error_code>(ret)));
        return false;
    }

    wimlib_capture_source capture_source;
    capture_source.fs_source_path=const_cast<wchar_t*>(sourceDirectory.c_str());
    capture_source.wim_target_path=const_cast<wimlib_tchar*>(WIMLIB_WIM_ROOT_PATH);
    capture_source.reserved=0;

    ret=wimlib_add_image_multisource(wim,&capture_source,1,imageName.c_str(),nullptr,add_flags);
    if(ret!=0){
        fwprintf(stderr,L"ERROR: Error adding image to WIM: %ls\n",wimlib_get_error_string(static_cast<wimlib_error_code>(ret)));
        wimlib_free(wim);
        return false;
    }

    // Set low priority right before the intensive write operation
    SetPriorityClass(GetCurrentProcess(),BELOW_NORMAL_PRIORITY_CLASS);

    wprintf(L"Writing WIM file using %u threads...\n",num_threads);
    if(appending){
        ret=wimlib_overwrite(wim,write_flags,num_threads);
    } else{
        ret=wimlib_write(wim,wimFile.c_str(),WIMLIB_ALL_IMAGES,write_flags,num_threads);
    }

    // Restore priority after the intensive operation is complete
    SetPriorityClass(GetCurrentProcess(),NORMAL_PRIORITY_CLASS);

    if(ret!=0){
        fwprintf(stderr,L"ERROR: Error writing WIM file: %ls\n",wimlib_get_error_string(static_cast<wimlib_error_code>(ret)));
        wimlib_free(wim);
        return false;
    }

    wimlib_free(wim);
    return true;
}


void CompileRegexPatterns(const std::vector<std::wstring>& strPat,std::vector<std::wregex>& aRegEx){
    aRegEx.clear();
    aRegEx.reserve(strPat.size());
    for(const auto& pat:strPat){
        try{
            aRegEx.emplace_back(pat,std::regex_constants::icase);
        } catch(const std::regex_error& e){
            std::wcerr<<L"ERROR: Failed to compile regex pattern: '"<<pat<<L"'\n";
            std::wcerr<<L"  - Reason: "<<e.what()<<L'\n';
        }
    }
}

std::wstring GetAppVersionString(const std::wstring& value_name){
    wchar_t module_path[MAX_PATH];
    if(GetModuleFileNameW(NULL,module_path,MAX_PATH)==0){
        return L"";
    }
    DWORD handle=0;
    DWORD info_size=GetFileVersionInfoSizeW(module_path,&handle);
    if(info_size==0){
        return L"";
    }
    std::vector<BYTE> version_info(info_size);
    if(!GetFileVersionInfoW(module_path,handle,info_size,version_info.data())){
        return L"";
    }
    struct LANGANDCODEPAGE{
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate;
    UINT translate_len=0;
    if(!VerQueryValueW(version_info.data(),L"\\VarFileInfo\\Translation",(LPVOID*)&lpTranslate,&translate_len)){
        return L"";
    }
    wchar_t query_path[256];
    swprintf_s(query_path,L"\\StringFileInfo\\%04x%04x\\%s",lpTranslate[0].wLanguage,lpTranslate[0].wCodePage,value_name.c_str());
    wchar_t* value_ptr=nullptr;
    UINT value_len=0;
    if(VerQueryValueW(version_info.data(),query_path,(LPVOID*)&value_ptr,&value_len)){
        return std::wstring(value_ptr);
    }
    return L"";
}

std::wstring GetUserProfileDirectory(){
    PWSTR pszPath=nullptr;
    HRESULT hr=SHGetKnownFolderPath(FOLDERID_Profile,0,NULL,&pszPath);

    if(SUCCEEDED(hr)){
        std::wstring userProfilePath(pszPath);
        CoTaskMemFree(pszPath); // Free the memory allocated by the API
        return userProfilePath;
    }
    return L""; // Return empty string on failure
}

static unsigned get_unit(uint64_t total_bytes,const wchar_t** name_ret){
    const uint64_t GIBIBYTE_MIN_NBYTES=10000000000ULL;
    const uint64_t MEBIBYTE_MIN_NBYTES=10000000ULL;
    const uint64_t KIBIBYTE_MIN_NBYTES=10000ULL;

    if(total_bytes>=GIBIBYTE_MIN_NBYTES){
        *name_ret=L"GiB";
        return 30;
    } else if(total_bytes>=MEBIBYTE_MIN_NBYTES){
        *name_ret=L"MiB";
        return 20;
    } else if(total_bytes>=KIBIBYTE_MIN_NBYTES){
        *name_ret=L"KiB";
        return 10;
    } else{
        *name_ret=L"bytes";
        return 0;
    }
}

static void report_scan_progress(const wimlib_progress_info::wimlib_progress_info_scan* scan,bool done){
    static wimlib_progress_info::wimlib_progress_info_scan last_scan_progress={0};

    uint64_t prev_count=last_scan_progress.num_nondirs_scanned+last_scan_progress.num_dirs_scanned;
    uint64_t cur_count=scan->num_nondirs_scanned+scan->num_dirs_scanned;

    if(done||prev_count==0||cur_count>=prev_count+100||cur_count%128==0){
        unsigned unit_shift;
        const wchar_t* unit_name;

        unit_shift=get_unit(scan->num_bytes_scanned,&unit_name);

        wprintf(L"\r%" PRIu64 L" %ls scanned (%" PRIu64 L" files, %" PRIu64 L" directories)    ",
                scan->num_bytes_scanned>>unit_shift,
                unit_name,
                scan->num_nondirs_scanned,
                scan->num_dirs_scanned);

        last_scan_progress=*scan;
    }
}

std::wstring GenerateTimestampedName(const std::wstring& backupName){
    auto now=std::chrono::system_clock::now();
    auto in_time_t=std::chrono::system_clock::to_time_t(now);
    std::tm buf={};
    localtime_s(&buf,&in_time_t);

    std::wstringstream ss;
    ss<<std::put_time(&buf,L"%Y.%m.%d,%H%M%S");
    return ss.str()+L"_"+backupName;
}


static enum wimlib_progress_status __cdecl
MyProgressCallback(enum wimlib_progress_msg msg,
                   union wimlib_progress_info* info,
                   void* user_context){
#define TO_PERCENT(n, d) (((d) == 0) ? 0 : ((n) * 100 / (d)))
    unsigned percent_done;
    unsigned unit_shift;
    const wchar_t* unit_name;

    switch(msg){
    case WIMLIB_PROGRESS_MSG_WRITE_STREAMS:
        percent_done=static_cast<unsigned>(TO_PERCENT(info->write_streams.completed_bytes,info->write_streams.total_bytes));
        unit_shift=get_unit(info->write_streams.total_bytes,&unit_name);
        wprintf(L"\rArchiving file data: %" PRIu64 L" %ls of %" PRIu64 L" %ls (%u%%) done",
                info->write_streams.completed_bytes>>unit_shift,unit_name,
                info->write_streams.total_bytes>>unit_shift,unit_name,percent_done);
        if(info->write_streams.completed_bytes>=info->write_streams.total_bytes){
            wprintf(L"\n");
        }
        break;

    case WIMLIB_PROGRESS_MSG_SCAN_BEGIN:
        wprintf(L"Scanning \"%ls\"...\n",info->scan.source);
        break;

    case WIMLIB_PROGRESS_MSG_SCAN_DENTRY:
        // **FIX:** Reverted to unscoped enums as per imagex.c and user feedback.
        if(info->scan.status==wimlib_progress_info::wimlib_progress_info_scan::WIMLIB_SCAN_DENTRY_OK){
            report_scan_progress(&info->scan,false);
        } else if(info->scan.status==wimlib_progress_info::wimlib_progress_info_scan::WIMLIB_SCAN_DENTRY_EXCLUDED){
            wprintf(L"\nExcluding \"%ls\" from capture\n",info->scan.cur_path);
        }
        break;

    case WIMLIB_PROGRESS_MSG_SCAN_END:
        report_scan_progress(&info->scan,true);
        wprintf(L"\n");
        break;

    case WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY:
        percent_done=static_cast<unsigned>(TO_PERCENT(info->integrity.completed_bytes,info->integrity.total_bytes));
        unit_shift=get_unit(info->integrity.total_bytes,&unit_name);
        wprintf(L"\rVerifying integrity of \"%ls\": %" PRIu64 L" %ls of %" PRIu64 L" %ls (%u%%) done",
                info->integrity.filename,info->integrity.completed_bytes>>unit_shift,unit_name,
                info->integrity.total_bytes>>unit_shift,unit_name,percent_done);
        if(info->integrity.completed_bytes==info->integrity.total_bytes){
            wprintf(L"\n");
        }
        break;

    case WIMLIB_PROGRESS_MSG_CALC_INTEGRITY:
        percent_done=static_cast<unsigned>(TO_PERCENT(info->integrity.completed_bytes,info->integrity.total_bytes));
        unit_shift=get_unit(info->integrity.total_bytes,&unit_name);
        wprintf(L"\rCalculating integrity table for WIM: %" PRIu64 L" %ls of %" PRIu64 L" %ls (%u%%) done",
                info->integrity.completed_bytes>>unit_shift,unit_name,
                info->integrity.total_bytes>>unit_shift,unit_name,percent_done);
        if(info->integrity.completed_bytes==info->integrity.total_bytes){
            wprintf(L"\n");
        }
        break;

    case WIMLIB_PROGRESS_MSG_TEST_FILE_EXCLUSION:
        info->test_file_exclusion.will_exclude=false;
        if(info->test_file_exclusion.path){
            DWORD attributes=GetFileAttributesW(info->test_file_exclusion.path);
            if(attributes!=INVALID_FILE_ATTRIBUTES){
                if((attributes&FILE_ATTRIBUTE_RECALL_ON_OPEN)||(attributes&FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)){
                    wprintf(L"\nExcluding cloud file: \"%ls\"\n",info->test_file_exclusion.path);
                    info->test_file_exclusion.will_exclude=true;
                    break;
                }
            }
            std::wstring_view current_path(info->test_file_exclusion.path);
            for(const auto& compiled_regex:g_reExclFlt){
                if(std::regex_search(current_path.begin(),current_path.end(),compiled_regex)){
                    wprintf(L"\nExcluding by filter: \"%ls\"\n",info->test_file_exclusion.path);
                    info->test_file_exclusion.will_exclude=true;
                    break;
                }
            }
            //std::wstring_view current_path(info->test_file_exclusion.path);
            //if(std::regex_search(current_path.begin(),current_path.end(),g_reExclFlt)){
            //    wprintf(L"\nExcluding by filter: \"%ls\"\n",info->test_file_exclusion.path);
            //    info->test_file_exclusion.will_exclude=true;
            //}
        }
        break;
    default:
        break;
    }
    fflush(stdout);
    return WIMLIB_PROGRESS_STATUS_CONTINUE;
}

void CompileSingleRegex(const std::vector<std::wstring>& strPat,std::wregex& re){
    if(strPat.empty()){
        return;
    }

    std::wstringstream ss;
    bool first=true;
    for(const auto& pat:strPat){
        if(!first){
            ss<<L"|";
        }
        ss<<L"(?:"<<pat<<L")";
        first=false;
    }

    try{
        re.assign(ss.str(),std::regex_constants::icase|std::regex_constants::optimize);
    } catch(const std::regex_error& e){
        std::wcerr<<L"ERROR: Failed to compile combined regex pattern!\n";
        std::wcerr<<L"  - Reason: "<<e.what()<<L'\n';
        // Note: Debugging this can be tricky. You might want to print ss.str() here.
    }
}