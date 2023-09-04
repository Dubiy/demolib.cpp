#ifndef VISITORID_H
#define VISITORID_H

#include <string>

namespace Gary {
    class VisitorId {
    public:
        VisitorId(const std::string& publicKey_);
        std::string getVisitorId();
    private:
        std::string publicKey_;

        std::string calculateHash(const std::string& input);
        std::string getSystemInfo();
        std::string getSystemInfoMac();
    };
}
#endif // VISITORID_H