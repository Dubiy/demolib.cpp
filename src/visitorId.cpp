#include "visitorId.h"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#ifdef _WIN32
    #include <windows.h>
#elif __linux__
    #include <unistd.h>
    #include <sys/utsname.h>
#elif __APPLE__
    #include <sys/utsname.h>
    #include <sys/sysctl.h>
    #include <CoreFoundation/CoreFoundation.h>
    #include <IOKit/IOKitLib.h>
#endif

namespace Gary {

VisitorId::VisitorId(const std::string& publicKey) : publicKey_(publicKey) {}

std::string VisitorId::getVisitorId()  {
    std::string systemInfo = getSystemInfo();
    return calculateHash(systemInfo);
}

std::string VisitorId::calculateHash(const std::string& input) {
    // Use your preferred cryptographic library to calculate a hash (e.g., OpenSSL)
    // This is just a placeholder, not actual hashing.

    std::cout << "calculateHash(): "  << input << std::endl;

    return input;
}



std::string VisitorId::getSystemInfo() {
        std::stringstream info;

        #ifdef _WIN32
            // Windows-specific information gathering
            SYSTEM_INFO systemInfo;
            GetSystemInfo(&systemInfo);
            info << "Windows|" << systemInfo.dwProcessorType << "|" << systemInfo.dwNumberOfProcessors;
        #elif __linux__
            // Linux-specific information gathering
            struct utsname unameData;
            uname(&unameData);
            info << "Linux|" << unameData.machine << "|" << unameData.release;
        #elif __APPLE__
            return VisitorId::getSystemInfoMac();
        #else
            info << "Unknown";
        #endif

        return info.str();
    }



    std::string VisitorId::getSystemInfoMac() {
        std::stringstream info;
        info << "macOS|";

        try {
            struct utsname unameData;
            uname(&unameData);
            info << unameData.machine << "|"; // arm64
            info << unameData.sysname << "|"; // Darwin
            info << unameData.nodename << "|"; // du.local
            info << unameData.release << "|"; // 22.5.0
            info << unameData.version << "|"; // Darwin Kernel Version 22.5.0: Mon Apr 24 20:52:24 PDT 2023; root:xnu-8796.121.2~5/RELEASE_ARM64_T6000
        } catch (const std::exception& e) {
            info << "Failed to get uname|";
        }

        
        try {
            const size_t len = 128; // Adjust the buffer size as needed
            char model[len];
            size_t model_len = len;

            sysctlbyname("hw.model", model, &model_len, NULL, 0);
            info << model << "|"; // MacBookPro18,3
        } catch (const std::exception& e) {
            info << "Failed to get hw.model|";
        }
        
        try {
            int mib[2];
            size_t len;
            mib[0] = CTL_HW;
            mib[1] = HW_NCPU;
            int cpuCount;
            len = sizeof(cpuCount);
            sysctl(mib, 2, &cpuCount, &len, NULL, 0);
            info  << cpuCount << "|" ; // 10
        } catch (const std::exception& e) {
            info  << "Failed to get cpu count|";
        }

        try {
            int mib[2];
            size_t len;
            mib[0] = CTL_HW;
            mib[1] = HW_MEMSIZE;
            uint64_t memorySize;
            len = sizeof(memorySize);

            sysctl(mib, 2, &memorySize, &len, NULL, 0);
            // Convert the memory size to human-readable format (e.g., GB)
            double memoryGB = static_cast<double>(memorySize) / (1024 * 1024 * 1024);

            info << std::to_string(memoryGB) + " GB" << "|"; // 32.000000 GB
        } catch (const std::exception& e) {
            info << "Failed to get memory size|";
        }
        

        try {
            io_service_t platformExpert = IOServiceGetMatchingService(MACH_PORT_NULL, IOServiceMatching("IOPlatformExpertDevice"));
            
            CFStringRef serialNumber = (CFStringRef)IORegistryEntryCreateCFProperty(platformExpert, CFSTR(kIOPlatformSerialNumberKey), kCFAllocatorDefault, 0);
            IOObjectRelease(platformExpert);

            const char* serialNumberStr = CFStringGetCStringPtr(serialNumber, kCFStringEncodingUTF8);
            if (serialNumberStr != nullptr) {
                std::string serial(serialNumberStr);
                CFRelease(serialNumber);
                info << serial << "|"; // LM139FM835
            }
            CFRelease(serialNumber);
        } catch (const std::exception& e) {
            info << "Failed to get serail number|";
        }
        return info.str();
    }



}
