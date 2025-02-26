#pragma once

#include "Poco/Net/Context.h"
#include "Poco/Net/DialogSocket.h"
#include "Poco/Net/MessageHeader.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/NetSSL.h"
#include "Poco/Net/SocketAddress.h"
#include "Poco/Net/X509Certificate.h"
#include "Poco/NumberFormatter.h"
#include "Poco/StreamCopier.h"

#include <Poco/Net/MailMessage.h>
#include <cstddef>
#include <functional>
#include <istream>
#include <memory>
#include <vector>

namespace Poco {
namespace Net {

POCO_DECLARE_EXCEPTION(Net_API, IMAPException, NetException)

class IMAPClientSession {
  public:
    enum { IMAP_PORT = 143 };

    struct FolderInfo
    /// Information returned by listFolders().
    {
        std::string name;
        std::string flags;
    };

    struct PartInfo {
        std::vector<std::string> attributes;
        std::vector<PartInfo> childs;
    };

    struct MessageInfo
    /// Information returned by listMessages().
    {
        std::string uid;
        std::string from;
        std::string to;
        std::string subject;
        std::string date;
        std::string flags;
        PartInfo parts;

        bool seen;
        bool forwarded;
        int size;

        // std::vector<PartInfo> parts;
    };

    struct FetchedParts {
        Poco::Net::MessageHeader header;
        std::string content;
    };

    struct FetchedMessage {
        Poco::Net::MailMessage message;
        std::vector<FetchedParts> parts;
        int sequence{};
    };

    typedef std::vector<FolderInfo> FolderInfoVec;
    typedef std::vector<MessageInfo> MessageInfoVec;

    explicit IMAPClientSession(const StreamSocket &socket);
    IMAPClientSession(const std::string &host, Poco::UInt16 port = IMAP_PORT);

    virtual bool checkCapability(const std::string &cap);

    virtual ~IMAPClientSession();

    void setTimeout(const Poco::Timespan &timeout);

    Poco::Timespan getTimeout() const;

    virtual void login(const std::string &username,
                       const std::string &password);

    void close();
    void noop();

    void idle(const std::function<bool(const std::string &)> &callback);

    virtual void capability();

    std::vector<std::string> &getCapability() { return _capability; }

    virtual void copyMessage(const std::string &uid,
                             const std::string &from_folder,
                             const std::string &to_folder);
    virtual void moveMessage(const std::string &uid,
                             const std::string &from_folder,
                             const std::string &to_folder);
    virtual void deleteMessage(const std::string &uid,
                               const std::string &folder, bool expunge = true);
    virtual void loadMessage(const std::string &folder, const std::string &uid,
                             std::string &message);

    virtual void createFolder(const std::string &folder);
    virtual void deleteFolder(const std::string &folder);
    virtual void listFolders(const std::string &root, FolderInfoVec &folders);

    virtual std::vector<std::string>
    searchMessages(const std::string &criteria);

    virtual std::vector<std::unique_ptr<FetchedMessage>>
    fetchMessagesRFC822(const std::string &message_set);

    virtual void selectFolder(const std::string &folder);

    virtual void listMessages(const std::string &folder,
                              const std::string &filter,
                              const std::string &order,
                              std::vector<std::string> &uids);
    virtual void getMessages(const std::string &folder,
                             std::vector<std::string> &uids,
                             MessageInfoVec &messages);

    virtual void subscribe(const std::string &folder);
    virtual void unsubscribe(const std::string &folder);

    virtual bool sendCommand(const std::string &command, std::string &response,
                             std::vector<std::string> &data);

    DialogSocket &socket() { return _socket; }

    std::string &folderSeparator() { return _folder_separator; }

    template <class T = std::string>
    static void tokenize(const T &str, std::vector<T> &tokens,
                         const T &delimiters, const T &parenthesis,
                         bool trimParenthesis = false) {
        T token;
        T opened_par;

        for (typename T::value_type c : str) {
            for (size_t i = 0; i < parenthesis.size(); i += 2) {
                // Open a new one.
                if (c == parenthesis[i]) {
                    // special case, when the open char = close char, a second
                    // ocurrence must close, not open a new one.
                    if (!(opened_par.size() > 0 &&
                          opened_par[opened_par.size() - 1] == c &&
                          parenthesis[i] == parenthesis[i + 1])) {
                        opened_par.push_back(parenthesis[i]);
                        continue;
                    }
                }

                // if close, check that if is already open.
                if (c == parenthesis[i + 1] && opened_par.size()) {
                    // Check if is the last open
                    if (parenthesis[i] == opened_par[opened_par.size() - 1]) {
                        // close it
                        opened_par.pop_back();
                    }
                }
            }

            if (opened_par.size() > 0 ||
                (delimiters.find(c) == std::string::npos)) {
                token += c;
            } else {
                // remove parenthesis if apply
                if (trimParenthesis) {
                    for (size_t i = 0; i < parenthesis.size(); i++) {
                        if (token.size() < 2)
                            break;
                        if (token[0] == parenthesis[i] &&
                            token[token.size() - 1] == parenthesis[i + 1])
                            token = token.substr(1, token.length() - 2);
                    }
                }
                tokens.push_back(token);
                token.clear();
            }
        }

        if (!token.empty()) {
            if (trimParenthesis) {
                for (size_t i = 0; i < parenthesis.size(); i++) {
                    if (token.size() < 2)
                        break;
                    if (token[0] == parenthesis[i] &&
                        token[token.size() - 1] == parenthesis[i + 1])
                        token = token.substr(1, token.length() - 2);
                }
            }
            tokens.push_back(token);
        }
    }

    std::string host() { return _host; }

  private:
    bool idleImpl(const std::function<bool(const std::string &)> &callback);

    void moveMessage_without_MOVE(const std::string &uid,
                                  const std::string &from_folder,
                                  const std::string &to_folder);
    PartInfo parseBodyStructure(std::istream &src);

    DialogSocket _socket;
    bool _isOpen;
    int _tag;
    std::string _curTag, _host;
    std::string _folder_separator;
    std::vector<std::string> _capability;
};

} // namespace Net
} // namespace Poco
