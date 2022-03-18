#ifndef ___BLUETOOTH_HCI_SOCKET_H___
#define ___BLUETOOTH_HCI_SOCKET_H___

#include <node.h>
#include <map>
#include <nan.h>
#include <memory>

// 1 minute in nanoseconds
#define L2_CONNECT_TIMEOUT 60000000000

typedef struct bdaddr_s {
  uint8_t b[6];

  bool operator<(const struct bdaddr_s& r) const {
    for(int i = 0; i < 6; i++) {
      if(b[i] >= r.b[i]) {
        return false;
      }
    }
    return true;
  }

} __attribute__((packed)) bdaddr_t;

struct sockaddr_l2 {
  sa_family_t    l2_family;
  unsigned short l2_psm;
  bdaddr_t       l2_bdaddr;
  unsigned short l2_cid;
  uint8_t        l2_bdaddr_type;
};

class BluetoothWriteWorker;
class BluetoothHciSocket;
class BluetoothCommunicator;

class BluetoothHciL2Socket {
  public:
  BluetoothHciL2Socket(BluetoothCommunicator* parent, unsigned char*, char, bdaddr_t, char, uint64_t expires);
  ~BluetoothHciL2Socket();
  void disconnect();
  void connect();
  void expires(uint64_t expires);
  uint64_t expires() const;
  bool connected() const;


  private:
  int _socket;
  BluetoothCommunicator* _parent;
  uint64_t _expires; // or 0 if connected
  struct sockaddr_l2 l2_src;
  struct sockaddr_l2 l2_dst;
};

class BluetoothCommunicator {
  friend class BluetoothHciSocket;
public:
  BluetoothCommunicator();
  ~BluetoothCommunicator();
  bool write(char* data, int length);
  void cleanup();
  void cleanup_l2(bdaddr_t bdaddr);
  int kernelDisconnectWorkArounds(char* data, int length);
private:
  int _devId;
  int _mode;
  int _socket;
  uint8_t _address[6];
  uint8_t _addressType;
  
  std::map<bdaddr_t, std::weak_ptr<BluetoothHciL2Socket>> _l2sockets_connected;
  std::map<bdaddr_t, std::shared_ptr<BluetoothHciL2Socket>> _l2sockets_connecting;
  std::map<unsigned short, std::shared_ptr<BluetoothHciL2Socket>> _l2sockets_handles;

  bool kernelConnectWorkArounds(char* data, int length);
  bool handleConnecting(bdaddr_t addr, char addrType);
  bool handleConnectionComplete(unsigned short handle, bdaddr_t addr, char addrType);
};

class BluetoothHciSocket : public node::ObjectWrap {
  friend class BluetoothHciL2Socket;
  friend class BluetoothWriteWorker;

public:
  static NAN_MODULE_INIT(Init);

  static NAN_METHOD(New);
  static NAN_METHOD(BindRaw);
  static NAN_METHOD(BindUser);
  static NAN_METHOD(BindControl);
  static NAN_METHOD(IsDevUp);
  static NAN_METHOD(GetDeviceList);
  static NAN_METHOD(SetFilter);
  static NAN_METHOD(Start);
  static NAN_METHOD(Stop);
  static NAN_METHOD(Write);
  static NAN_METHOD(KernelDisconnectWorkArounds);
  static NAN_METHOD(Cleanup);

private:
  BluetoothHciSocket();
  ~BluetoothHciSocket();

  std::shared_ptr<BluetoothCommunicator> _communicator;

  void start();
  int bindRaw(int* devId);
  int bindUser(int* devId);
  void bindControl();
  bool isDevUp();
  void setFilter(char* data, int length);
  void stop();
  void cleanup_l2(bdaddr_t addr);
  void poll();

  void emitErrnoError(const char *syscall);
  int devIdFor(const int* devId, bool isUp);

  static void PollCloseCallback(uv_poll_t* handle);
  static void PollCallback(uv_poll_t* handle, int status, int events);

private:
  Nan::Persistent<v8::Object> This;

  uv_poll_t _pollHandle;

  static Nan::Persistent<v8::FunctionTemplate> constructor_template;
};

#endif
