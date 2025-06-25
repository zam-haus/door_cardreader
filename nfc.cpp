#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>


// Helper: URI Identifier Codes (NFCForum-TS-RTD_URI_1.0)
// NFC URI Identifier Codes
static const uint8_t URI_PREFIX_NONE[]         = { 0x00 }; // (no prefix)
static const uint8_t URI_PREFIX_HTTP_WWW[]     = { 0x01 }; // "http://www."
static const uint8_t URI_PREFIX_HTTPS_WWW[]    = { 0x02 }; // "https://www."
static const uint8_t URI_PREFIX_HTTP[]         = { 0x03 }; // "http://"
static const uint8_t URI_PREFIX_HTTPS[]        = { 0x04 }; // "https://"
static const uint8_t URI_PREFIX_TEL[]          = { 0x05 }; // "tel:"
static const uint8_t URI_PREFIX_MAILTO[]       = { 0x06 }; // "mailto:"
static const uint8_t URI_PREFIX_FTP_ANON[]     = { 0x07 }; // "ftp://anonymous:"
static const uint8_t URI_PREFIX_FTP_FTP[]      = { 0x08 }; // "ftp://ftp."
static const uint8_t URI_PREFIX_FTPS[]         = { 0x09 }; // "ftps://"
static const uint8_t URI_PREFIX_SFTP[]         = { 0x0A }; // "sftp://"
static const uint8_t URI_PREFIX_SMB[]          = { 0x0B }; // "smb://"
static const uint8_t URI_PREFIX_NFS[]          = { 0x0C }; // "nfs://"
static const uint8_t URI_PREFIX_FTP[]          = { 0x0D }; // "ftp://"
static const uint8_t URI_PREFIX_DAV[]          = { 0x0E }; // "dav://"
static const uint8_t URI_PREFIX_NEWS[]         = { 0x0F }; // "news:"
static const uint8_t URI_PREFIX_TELNET[]       = { 0x10 }; // "telnet://"
static const uint8_t URI_PREFIX_IMAP[]         = { 0x11 }; // "imap:"
static const uint8_t URI_PREFIX_RTSP[]         = { 0x12 }; // "rtsp://"
static const uint8_t URI_PREFIX_URN[]          = { 0x13 }; // "urn:"
static const uint8_t URI_PREFIX_POP[]          = { 0x14 }; // "pop:"
static const uint8_t URI_PREFIX_SIP[]          = { 0x15 }; // "sip:"
static const uint8_t URI_PREFIX_SIPS[]         = { 0x16 }; // "sips:"
static const uint8_t URI_PREFIX_TFTP[]         = { 0x17 }; // "tftp:"
static const uint8_t URI_PREFIX_BTSPP[]        = { 0x18 }; // "btspp://"
static const uint8_t URI_PREFIX_BTL2CAP[]      = { 0x19 }; // "btl2cap://"
static const uint8_t URI_PREFIX_BTGOEP[]       = { 0x1A }; // "btgoep://"
static const uint8_t URI_PREFIX_TCPOBEX[]      = { 0x1B }; // "tcpobex://"
static const uint8_t URI_PREFIX_IRDAOBEX[]     = { 0x1C }; // "irdaobex://"
static const uint8_t URI_PREFIX_FILE[]         = { 0x1D }; // "file://"
static const uint8_t URI_PREFIX_URN_EPC_ID[]   = { 0x1E }; // "urn:epc:id:"
static const uint8_t URI_PREFIX_URN_EPC_TAG[]  = { 0x1F }; // "urn:epc:tag:"
static const uint8_t URI_PREFIX_URN_EPC_PAT[]  = { 0x20 }; // "urn:epc:pat:"
static const uint8_t URI_PREFIX_URN_EPC_RAW[]  = { 0x21 }; // "urn:epc:raw:"
static const uint8_t URI_PREFIX_URN_EPC[]      = { 0x22 }; // "urn:epc:"
static const uint8_t URI_PREFIX_URN_NFC[]      = { 0x23 }; // "urn:nfc:"

std::vector<uint8_t> createUriMessage(const std::string& uri) {
    uint8_t header = 0xD1; // MB=1, ME=1, SR=1, TNF=0x1 (well-known)
    uint8_t typeLength = 1; // 'U'
    uint8_t payloadLength = 1 + uri.size(); // URI Identifier Code + URI

    std::vector<uint8_t> outBuffer;
    outBuffer.reserve(5 + uri.size());

    outBuffer.push_back(header);
    outBuffer.push_back(typeLength);
    outBuffer.push_back(payloadLength);
    outBuffer.push_back('U'); // Type field for URI Record
    outBuffer.push_back(URI_PREFIX_HTTPS[0]); // URI Identifier Code

    outBuffer.insert(outBuffer.end(), uri.begin(), uri.end());

    return outBuffer;
}

int main(int argc, char *argv[]) {
    auto ndef = createUriMessage("sesam.zam.haus/");
    std::cout.write(reinterpret_cast<const char*>(ndef.data()), ndef.size());
    return 0;
}
