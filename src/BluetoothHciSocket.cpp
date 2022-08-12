#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <node_buffer.h>
#include <nan.h>

#include "BluetoothHciSocket.h"

#define BTPROTO_L2CAP 0
#define BTPROTO_HCI 1

#define SOL_HCI 0
#define HCI_FILTER 2

#define HCIGETDEVLIST _IOR('H', 210, int)
#define HCIGETDEVINFO _IOR('H', 211, int)

#define HCI_CHANNEL_RAW 0
#define HCI_CHANNEL_USER 1
#define HCI_CHANNEL_CONTROL 3

#define HCI_DEV_NONE 0xffff

#define HCI_MAX_DEV 16

#define ATT_CID 4

#define ADDRESS_LOG(address) address.b[5], address.b[4], address.b[3], address.b[2], address.b[1], address.b[0]

const char DisconnectedReason[] = "disconnection command";

enum
{
  HCI_UP,
  HCI_INIT,
  HCI_RUNNING,

  HCI_PSCAN,
  HCI_ISCAN,
  HCI_AUTH,
  HCI_ENCRYPT,
  HCI_INQUIRY,

  HCI_RAW,
};

struct sockaddr_hci
{
  sa_family_t hci_family;
  unsigned short hci_dev;
  unsigned short hci_channel;
};

struct hci_dev_req
{
  uint16_t dev_id;
  uint32_t dev_opt;
};

struct hci_dev_list_req
{
  uint16_t dev_num;
  struct hci_dev_req dev_req[0];
};

struct hci_dev_info
{
  uint16_t dev_id;
  char name[8];

  bdaddr_t bdaddr;

  uint32_t flags;
  uint8_t type;

  uint8_t features[8];

  uint32_t pkt_type;
  uint32_t link_policy;
  uint32_t link_mode;

  uint16_t acl_mtu;
  uint16_t acl_pkts;
  uint16_t sco_mtu;
  uint16_t sco_pkts;

  // hci_dev_stats
  uint32_t err_rx;
  uint32_t err_tx;
  uint32_t cmd_tx;
  uint32_t evt_rx;
  uint32_t acl_tx;
  uint32_t acl_rx;
  uint32_t sco_tx;
  uint32_t sco_rx;
  uint32_t byte_rx;
  uint32_t byte_tx;
};

using namespace v8;

Nan::Persistent<FunctionTemplate> BluetoothHciSocket::constructor_template;

NAN_MODULE_INIT(BluetoothHciSocket::Init)
{
  Nan::HandleScope scope;

  Local<FunctionTemplate> tmpl = Nan::New<FunctionTemplate>(New);
  constructor_template.Reset(tmpl);

  tmpl->InstanceTemplate()->SetInternalFieldCount(1);
  tmpl->SetClassName(Nan::New("BluetoothHciSocket").ToLocalChecked());

  Nan::SetPrototypeMethod(tmpl, "prepare", Prepare);
  Nan::SetPrototypeMethod(tmpl, "start", Start);
  Nan::SetPrototypeMethod(tmpl, "bindRaw", BindRaw);
  Nan::SetPrototypeMethod(tmpl, "bindUser", BindUser);
  Nan::SetPrototypeMethod(tmpl, "bindControl", BindControl);
  Nan::SetPrototypeMethod(tmpl, "isDevUp", IsDevUp);
  Nan::SetPrototypeMethod(tmpl, "getDeviceList", GetDeviceList);
  Nan::SetPrototypeMethod(tmpl, "setFilter", SetFilter);
  Nan::SetPrototypeMethod(tmpl, "info", Info);
  Nan::SetPrototypeMethod(tmpl, "stop", Stop);
  Nan::SetPrototypeMethod(tmpl, "write", Write);
  Nan::SetPrototypeMethod(tmpl, "kernelDisconnectWorkArounds", KernelDisconnectWorkArounds);
  Nan::SetPrototypeMethod(tmpl, "kernelConnectWorkArounds", KernelConnectWorkArounds);
  Nan::SetPrototypeMethod(tmpl, "cleanup", Cleanup);

  Nan::Set(target, Nan::New("BluetoothHciSocket").ToLocalChecked(), Nan::GetFunction(tmpl).ToLocalChecked());
}

BluetoothCommunicator::BluetoothCommunicator(bool debug) : _socket(-1),
                                                           _mode(0),
                                                           _devId(0),
                                                           _address(),
                                                           _addressType(0),
                                                           _debug(debug)
{
}

BluetoothHciSocket::BluetoothHciSocket() : node::ObjectWrap(),
                                           _pollHandle(),
                                           _communicator(nullptr)
{
}

BluetoothHciSocket::~BluetoothHciSocket()
{
  uv_close((uv_handle_t *)&this->_pollHandle, (uv_close_cb)BluetoothHciSocket::PollCloseCallback);
}

NAN_METHOD(BluetoothHciSocket::Prepare)
{
  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());
  int zero = 0;

  Local<Value> arg0 = info[0];
  if (!arg0->IsBoolean())
  {
    Nan::ThrowError("Debug must be boolean");
    return;
  }

  p->_communicator.reset(new BluetoothCommunicator(arg0->BooleanValue(Nan::GetCurrentContext()->GetIsolate())));

  int fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
  if (fd == -1)
  {
    Nan::ThrowError(Nan::ErrnoException(errno, "socket"));
    return;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &zero, sizeof(zero)) < 0)
  {
    Nan::ThrowError(Nan::ErrnoException(errno, "setsockopt"));
    return;
  }

  p->_communicator->_socket = fd;

  if (uv_poll_init(uv_default_loop(), &p->_pollHandle, p->_communicator->_socket) < 0)
  {
    Nan::ThrowError("uv_poll_init failed");
    return;
  }

  p->_pollHandle.data = p;
}

void BluetoothHciL2Socket::connect(const char *reason)
{
  _socket = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
  if (_socket < 0)
    return;

  _parent->log("BluetoothHCISocket: Connecting to %02x:%02x:%02x:%02x:%02x:%02x with socket %d due to %s\n", ADDRESS_LOG(address), _socket, reason);

  if (bind(_socket, (struct sockaddr *)&l2_src, sizeof(l2_src)) < 0)
  {
    _parent->log("BluetoothHCISocket: Connecting to %02x:%02x:%02x:%02x:%02x:%02x with socket %d failed due to bind error\n", ADDRESS_LOG(address), _socket);
    close(_socket);
    _socket = -1;
    return;
  }

  // the kernel needs to flush the socket before we continue
  while (::connect(_socket, (struct sockaddr *)&l2_dst, sizeof(l2_dst)) == -1)
  {
    if (errno == EINTR)
    {
      continue;
    }
    _parent->log("BluetoothHCISocket: Failed connection to %02x:%02x:%02x:%02x:%02x:%02x (socket %d) with errno %d\n", ADDRESS_LOG(address), _socket, errno);
    close(_socket);
    _socket = -1;
    return;
  }

  _parent->log("BluetoothHCISocket: Connected to %02x:%02x:%02x:%02x:%02x:%02x socket %d\n", ADDRESS_LOG(address), _socket);
}

void BluetoothHciL2Socket::disconnect(const char *reason)
{
  if (this->_socket != -1)
  {
    _parent->log("BluetoothHCISocket: Disconnecting from  %02x:%02x:%02x:%02x:%02x:%02x (socket: %d, handle: %d) due to %s\n", ADDRESS_LOG(address), _socket, handle, reason);
    close(this->_socket);
    this->_socket = -1;
  }
}

void BluetoothHciL2Socket::expires(uint64_t expires)
{
  _expires = expires;
}

uint64_t BluetoothHciL2Socket::expires() const
{
  return _expires;
}

bool BluetoothHciL2Socket::connected() const
{
  return this->_socket != -1;
}

static unsigned short htobs(unsigned short v)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  return v;
#elif __BYTE_ORDER == __BIG_ENDIAN
  return bswap_16(v);
#else
#error "Unknown byte order"
#endif
}

BluetoothHciL2Socket::BluetoothHciL2Socket(BluetoothCommunicator *parent, bdaddr_t srcaddr, char srcType, bdaddr_t bdaddr, char bdaddrType, uint64_t expires) : _parent(parent), address(bdaddr), reason(nullptr), handle(-1), _expires(expires), l2_src({}), l2_dst({})
{
  unsigned short l2cid = htobs(ATT_CID);

  memset(&l2_src, 0, sizeof(l2_src));
  l2_src.l2_family = AF_BLUETOOTH;
  l2_src.l2_cid = l2cid;
  memcpy(&l2_src.l2_bdaddr, srcaddr.b, sizeof(l2_src.l2_bdaddr));
  l2_src.l2_bdaddr_type = srcType;
  // l2_src.l2_psm = 0;

  memset(&l2_dst, 0, sizeof(l2_dst));
  l2_dst.l2_family = AF_BLUETOOTH;
  memcpy(&l2_dst.l2_bdaddr, &bdaddr, sizeof(l2_dst.l2_bdaddr));
  l2_dst.l2_cid = l2cid;
  l2_dst.l2_bdaddr_type = bdaddrType; // BDADDR_LE_PUBLIC (0x01), BDADDR_LE_RANDOM (0x02)
                                      // l2_dst.l2_psm = 0;
}

void BluetoothHciSocket::cleanup_l2(unsigned short handle)
{
  _communicator->cleanup_l2(handle);
}

void BluetoothCommunicator::cleanup_l2(unsigned short handle)
{
  auto it = _l2sockets_connected.find(handle);
  if (it != _l2sockets_connected.end())
  {
    it->second->reason = "cleanup";
    _l2sockets_connected.erase(it);
  }
  else
  {
    this->log("Got request to cleanup handle %d but we don't have it\n", handle);
  }
}

void BluetoothCommunicator::log(const char *format, ...)
{
  if (!this->_debug)
    return;
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

BluetoothHciL2Socket::~BluetoothHciL2Socket()
{
  if (this->_socket != -1)
    disconnect(this->reason ? this->reason : "destruction");
  if (_expires == 0 && handle >= 0 && reason != DisconnectedReason)
  {
    this->_parent->cleanup_l2(handle);
  }
}

void BluetoothHciSocket::start()
{
  if (uv_poll_start(&this->_pollHandle, UV_READABLE, BluetoothHciSocket::PollCallback) < 0)
  {
    Nan::ThrowError("uv_poll_start failed");
  }
}

void BluetoothHciSocket::bindCommon()
{
  struct hci_dev_info di = {};

  // get the local address and address type
  memset(&di, 0x00, sizeof(di));
  di.dev_id = this->_communicator->_devId;
  memset(this->_communicator->_address.b, 0, sizeof(this->_communicator->_address.b));
  this->_communicator->_addressType = 0;

  if (ioctl(this->_communicator->_socket, HCIGETDEVINFO, (void *)&di) > -1)
  {
    memcpy(this->_communicator->_address.b, &di.bdaddr, sizeof(di.bdaddr));
    this->_communicator->_addressType = di.type;

    if (this->_communicator->_addressType == 3)
    {
      // 3 is a weird type, use 1 (public) instead
      this->_communicator->_addressType = 1;
    }
  }
}

int BluetoothHciSocket::bindRaw(int *devId)
{
  struct sockaddr_hci a = {};

  a.hci_family = AF_BLUETOOTH;
  a.hci_dev = this->devIdFor(devId, true);
  a.hci_channel = HCI_CHANNEL_RAW;

  this->_communicator->_devId = a.hci_dev;
  this->_communicator->_mode = HCI_CHANNEL_RAW;

  if (bind(this->_communicator->_socket, (struct sockaddr *)&a, sizeof(a)) < 0)
  {
    Nan::ThrowError(Nan::ErrnoException(errno, "bind"));
    return -1;
  }

  bindCommon();

  return this->_communicator->_devId;
}

int BluetoothHciSocket::bindUser(int *devId)
{
  struct sockaddr_hci a = {};

  a.hci_family = AF_BLUETOOTH;
  a.hci_dev = this->devIdFor(devId, false);
  a.hci_channel = HCI_CHANNEL_USER;

  this->_communicator->_devId = a.hci_dev;

  if (bind(this->_communicator->_socket, (struct sockaddr *)&a, sizeof(a)) < 0)
  {
    this->_communicator->_mode = HCI_CHANNEL_RAW;
    Nan::ThrowError(Nan::ErrnoException(errno, "bind"));
    return -1;
  }

  this->_communicator->_mode = HCI_CHANNEL_USER;

  bindCommon();

  return this->_communicator->_devId;
}

void BluetoothHciSocket::bindControl()
{
  struct sockaddr_hci a = {};

  a.hci_family = AF_BLUETOOTH;
  a.hci_dev = HCI_DEV_NONE;
  a.hci_channel = HCI_CHANNEL_CONTROL;

  this->_communicator->_mode = HCI_CHANNEL_CONTROL;

  if (bind(this->_communicator->_socket, (struct sockaddr *)&a, sizeof(a)) < 0)
  {
    Nan::ThrowError(Nan::ErrnoException(errno, "bind"));
    return;
  }
}

bool BluetoothHciSocket::isDevUp()
{
  struct hci_dev_info di = {};
  bool isUp = false;

  if(this->_communicator->_mode == HCI_CHANNEL_USER) {
    return true;
  }

  di.dev_id = this->_communicator->_devId;

  if (ioctl(this->_communicator->_socket, HCIGETDEVINFO, (void *)&di) > -1)
  {
    isUp = (di.flags & (1 << HCI_UP)) != 0;
  }

  return isUp;
}

void BluetoothHciSocket::setFilter(char *data, int length)
{
  if (setsockopt(this->_communicator->_socket, SOL_HCI, HCI_FILTER, data, length) < 0)
  {
    this->emitErrnoError("setsockopt");
  }
}

void BluetoothHciSocket::poll()
{
  Nan::HandleScope scope;

  int length = 0;
  char data[1024];

  do
  {
    length = read(this->_communicator->_socket, data, sizeof(data));
    if (length < 0)
    {
      if (errno != EAGAIN && errno != EINTR)
      {
        this->emitErrnoError("read");
      }
      return;
    }

    Nan::AsyncResource res("BluetoothHciSocket::poll");

    Local<Value> argv[1] = {
        Nan::CopyBuffer(data, length).ToLocalChecked()};

    auto nThis = Nan::New<Object>(this->This);
    auto nEmit = Nan::New("_emitData").ToLocalChecked();

    if (length > 0)
    {
      res.runInAsyncScope(
             nThis, nEmit, 1,
             argv)
          .FromMaybe(v8::Local<v8::Value>());
    }
  } while (true);
}

void BluetoothHciSocket::stop()
{
  uv_poll_stop(&this->_pollHandle);
}

bool BluetoothCommunicator::write(char *data, int length)
{
  while (::write(this->_socket, data, length) < 0)
  {
    if (errno != EAGAIN && errno != EINTR)
    {
      return false;
    }
  }

  return true;
}

void BluetoothHciSocket::emitErrnoError(const char *syscall)
{
  v8::Local<v8::Value> error = Nan::ErrnoException(errno, syscall, strerror(errno));

  Local<Value> argv[2] = {
      Nan::New("error").ToLocalChecked(),
      error};
  Nan::AsyncResource res("BluetoothHciSocket::emitErrnoError");
  res.runInAsyncScope(
         Nan::New<Object>(this->This),
         Nan::New("emit").ToLocalChecked(),
         2,
         argv)
      .FromMaybe(v8::Local<v8::Value>());
}

int BluetoothHciSocket::devIdFor(const int *pDevId, bool isUp)
{
  int devId = 0; // default

  if (pDevId == nullptr)
  {
    struct hci_dev_list_req *dl;
    struct hci_dev_req *dr;

    dl = (hci_dev_list_req *)calloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl), 1);
    dr = dl->dev_req;

    dl->dev_num = HCI_MAX_DEV;

    if (ioctl(this->_communicator->_socket, HCIGETDEVLIST, dl) > -1)
    {
      for (int i = 0; i < dl->dev_num; i++, dr++)
      {
        bool devUp = dr->dev_opt & (1 << HCI_UP);
        bool match = (isUp == devUp);

        if (match)
        {
          // choose the first device that is match
          // later on, it would be good to also HCIGETDEVINFO and check the HCI_RAW flag
          devId = dr->dev_id;
          break;
        }
      }
    }

    free(dl);
  }
  else
  {
    devId = *pDevId;
  }

  return devId;
}

bool BluetoothCommunicator::handleConnectionComplete(unsigned short handle, bdaddr_t addr, char addrType)
{
  // printf("HCI_EV_LE_CONN_COMPLETE for handle %d\n", handle);

  std::shared_ptr<BluetoothHciL2Socket> l2socket_ptr;


  _l2sockets_mutex.lock();
  auto it = _l2sockets_connected.find(handle);
  if (it != _l2sockets_connected.end())
  {
    _l2sockets_mutex.unlock();
    if (memcmp(&it->second->address, &addr, sizeof(addr)) != 0)
    {
      it->second->disconnect("duplicate handle");
    }
    else
    {
      this->log("Got a second handle for the same device");
      return true;
    }
  }else{  
    _l2sockets_mutex.unlock();
  }


  _l2sockets_mutex.lock();
  auto it2 = _l2sockets_connecting.find(addr);
  if (it2 != _l2sockets_connecting.end())
  {
    // successful connection (we have a handle for the socket!)
    l2socket_ptr = it2->second;
    l2socket_ptr->expires(0);
    l2socket_ptr->reason = "connected";
    l2socket_ptr->handle = handle;
    assert(l2socket_ptr != nullptr);
    _l2sockets_connecting.erase(it2);
    assert(l2socket_ptr != nullptr);
    l2socket_ptr->reason = NULL;
  _l2sockets_mutex.unlock();
  }
  else
  {  
    _l2sockets_mutex.unlock();
    l2socket_ptr = std::make_shared<BluetoothHciL2Socket>(this, _address, _addressType, addr, addrType, 0);
    l2socket_ptr->connect("connection response");
  }
  

  if (!l2socket_ptr->connected())
  {
    this->log("Failed to connect to %02x:%02x:%02x:%02x:%02x:%02x while handling connection complete\n", ADDRESS_LOG(addr));
    l2socket_ptr->reason = "connect() failed";
    return false;
  }

  // we are connected (store)
  l2socket_ptr->handle = handle;
  
  _l2sockets_mutex.lock();
  this->_l2sockets_connected[handle] = l2socket_ptr;
  _l2sockets_mutex.unlock();

  return true;
}

const char *BluetoothCommunicator::kernelDisconnectWorkArounds(char *data, int length)
{
  if (this->_mode != HCI_CHANNEL_RAW || data[0] != 0x04)
  {
    return nullptr;
  }

  // HCI Event - LE Meta Event - LE Connection Complete => manually create L2CAP socket to force kernel to book keep
  // this socket will be closed on disconnection

  // The if statement:
  // data[0] = LE Meta Event (HCI_EVENT_PKT)
  // data[1] = HCI_EV_LE_META
  // data[2] = plen (0x13)
  // data[3] = HCI_EV_LE_CONN_COMPLETE (0x01)
  // data[4] = Status (0x00 = Success)
  // data[5,6] = handle (little endian)
  // data[7] = role (0x00 = Master)
  // data[9,]  = device bt address
  if (length == 22 && data[1] == 0x3e && data[2] == 0x13 && data[3] == 0x01 && data[4] == 0x00)
  { //  && data[7] == 0x01
    unsigned short handle = *((unsigned short *)(&data[5]));
    if (handle == 0)
    {
      return nullptr;
    }
    if (!this->handleConnectionComplete(handle, *(bdaddr_t *)&data[9], data[8] + 1))
    {
      return "failed connection";
    }

    return nullptr; // "handled connection";
  }
  else if (length == 7 && data[1] == 0x05 && data[2] == 0x04 && data[3] == 0x00)
  {

    // HCI Event - Disconn Complete =======================> close socket from above
    // This uses handle, response (so handle is at offset 4)
    unsigned short handle = *((unsigned short *)(&data[4]));
    if (handle == 0)
    {
      return nullptr;
    }

    
    _l2sockets_mutex.lock();
    // printf("Disconn Complete for handle %d (%d)\n", handle, this->_l2sockets_handles.count(handle));
    auto it = this->_l2sockets_connected.find(handle);
    if (it != this->_l2sockets_connected.end())
    {
      it->second->reason = DisconnectedReason;
      this->_l2sockets_connected.erase(it);
    }

    _l2sockets_mutex.unlock();
    return nullptr;
  }
  else if (length == 34 && data[1] == 0x3e && data[3] == 0x0a && data[4] == 0x00)
  {
    // Enhanced connection complete event
    // 04 3e 1f 0a 00 10 00 00 00 67 c3 2e 6f 7c b8 00 00 00 00 00 00 00 00 00 00 00 00 24 00 00 00 2a 00 00
    unsigned short handle = *((unsigned short *)(&data[5]));
    if (handle == 0)
    {
      return nullptr;
    }

    if (!this->handleConnectionComplete(handle, *(bdaddr_t *)&data[9], data[8] + 1))
    {
      return "failed enhanced connection";
    }

    return nullptr; //"handled connection";
  }

  return nullptr;
}

const char *BluetoothCommunicator::handleConnecting(bdaddr_t addr, char addrType)
{
  std::shared_ptr<BluetoothHciL2Socket> l2socket_ptr;
  _l2sockets_mutex.lock();
  if (this->_l2sockets_connecting.find(addr) != this->_l2sockets_connecting.end())
  {
    // we were connecting but now we connect again
    l2socket_ptr = this->_l2sockets_connecting[addr];  
    l2socket_ptr->disconnect("refresh, already connecting");
    l2socket_ptr->expires(uv_hrtime() + L2_CONNECT_TIMEOUT);
    _l2sockets_mutex.unlock();
    l2socket_ptr->connect("connection request (refresh)");
    if (!l2socket_ptr->connected())
    {
      return "connect failed";
    }
  }
  else
  {
    _l2sockets_mutex.unlock();
    // 60000000000  = 1 minute
    l2socket_ptr = std::make_shared<BluetoothHciL2Socket>(this, _address, _addressType, addr, addrType, uv_hrtime() + L2_CONNECT_TIMEOUT);
    l2socket_ptr->expires(uv_hrtime() + L2_CONNECT_TIMEOUT);
    _l2sockets_mutex.lock();
    this->_l2sockets_connecting[addr] = l2socket_ptr;
    _l2sockets_mutex.unlock();
    l2socket_ptr->connect("connection request");
    if (!l2socket_ptr->connected())
    {
      _l2sockets_mutex.lock();
      this->_l2sockets_connecting.erase(addr);
      _l2sockets_mutex.unlock();
      return "connect failed";
    }
  }

  // returns true to skip sending the kernel this commoand
  // the command will instead be sent by the connect() operation
  return "handled connect";
}

bool BluetoothCommunicator::shouldWrite(char *data, int length)
{
  if(this->_mode == HCI_CHANNEL_USER) {
    return true;
  }

  if (length > 14 && data[0] == 0x01 && data[1] == 0x43 && data[2] == 0x20)
  {
    return false;
  }

  if (length == 29 && data[0] == 0x01 && data[1] == 0x0d && data[2] == 0x20 && data[3] == 0x19)
  {
    return false;
  }

  return true;
}

bool BluetoothCommunicator::shouldConnectWorkaround(char *data, int length)
{
  if(this->_mode == HCI_CHANNEL_USER) {
    return false;
  }

  if (length > 14 && data[0] == 0x01 && data[1] == 0x43 && data[2] == 0x20)
  {
    return true;
  }

  if (length == 29 && data[0] == 0x01 && data[1] == 0x0d && data[2] == 0x20 && data[3] == 0x19)
  {
    return true;
  }

  // cancel connection attempt
  if (length >= 4 && data[0] == 0x01 && data[1] == 0x0e && data[2] == 0x20 && data[3] == 0x00)
  {
    return true;
  }

  return false;
}

const char *BluetoothCommunicator::kernelConnectWorkArounds(char *data, int length)
{
  if (this->_mode != HCI_CHANNEL_RAW)
  {
    return nullptr;
  }

  const char* ret = nullptr;

  // if statement:
  // data[0]: HCI_COMMAND_PKT
  // data[1,2]: HCI_OP_LE_ENH_CREATE_CONN (0x2043)
  // data[3]: plen
  // data[8 ...] payload
  if (length > 14 && data[0] == 0x01 && data[1] == 0x43 && data[2] == 0x20)
  {
    ret = this->handleConnecting(*(bdaddr_t *)&data[7], data[6] + 1);
  }

  // if statement:
  // data[0]: HCI_COMMAND_PKT
  // data[1,2]: HCI_OP_LE_CREATE_CONN (0x200d)
  // data[3]: plen
  // data[10 ...] addr

  else if (length == 29 && data[0] == 0x01 && data[1] == 0x0d && data[2] == 0x20 && data[3] == 0x19)
  {
    ret = this->handleConnecting(*(bdaddr_t *)&data[10], data[9] + 1);
  }

  // cancel connection attempt
  else if (length >= 4 && data[0] == 0x01 && data[1] == 0x0e && data[2] == 0x20 && data[3] == 0x00)
  {
    _l2sockets_mutex.lock();
    for (auto it = this->_l2sockets_connecting.begin(); it != this->_l2sockets_connecting.end(); it++)
    {
      it->second->disconnect("cancel");
    }
    this->_l2sockets_connecting.clear();
    _l2sockets_mutex.unlock();
  }

  return ret; // continue and do write
}

class BluetoothCleanupWorker : public Nan::AsyncWorker
{
public:
  // Constructor
  BluetoothCleanupWorker(Nan::Callback *callback, std::shared_ptr<BluetoothCommunicator> socket)
      : AsyncWorker(callback, "BluetoothCleanupWorker"), _socket(socket) {}
  // Destructor
  ~BluetoothCleanupWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute()
  {
    this->_socket->cleanup();
  }

private:
  std::shared_ptr<BluetoothCommunicator> _socket;
};

class BluetoothWriteWorker : public Nan::AsyncWorker
{
public:
  // Constructor
  BluetoothWriteWorker(Nan::Callback *callback, std::shared_ptr<BluetoothCommunicator> socket, char *data, int length)
      : AsyncWorker(callback, "BluetoothWriteWorker"), _socket(socket), _data(data), _length(length) {}
  // Destructor
  ~BluetoothWriteWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute()
  {
    if (!_socket->write(_data, _length))
    {
      SetErrorMessage("write");
    }
  }

private:
  std::shared_ptr<BluetoothCommunicator> _socket;
  char *_data;
  int _length;
};

class BluetoothDisconnectWorker : public Nan::AsyncWorker
{
public:
  // Constructor
  BluetoothDisconnectWorker(Nan::Callback *callback, std::shared_ptr<BluetoothCommunicator> socket, char *data, int length)
      : AsyncWorker(callback, "BluetoothDisconnectWorker"), _socket(socket), _data(data), _length(length) {}
  // Destructor
  ~BluetoothDisconnectWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute()
  {
    const char *reason = this->_socket->kernelDisconnectWorkArounds(_data, _length);
    if (reason != nullptr)
    {
      SetErrorMessage(reason);
    }
  }

private:
  std::shared_ptr<BluetoothCommunicator> _socket;
  char *_data;
  int _length;
};

class BluetoothConnectWorker : public Nan::AsyncWorker
{
public:
  // Constructor
  BluetoothConnectWorker(Nan::Callback *callback, std::shared_ptr<BluetoothCommunicator> socket, char *data, int length)
      : AsyncWorker(callback, "BluetoothConnectWorker"), _socket(socket), _data(data), _length(length) {}
  // Destructor
  ~BluetoothConnectWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute()
  {
    const char *err = this->_socket->kernelConnectWorkArounds(_data, _length);
    if (err != nullptr)
    {
      SetErrorMessage(err);
    }
  }

private:
  std::shared_ptr<BluetoothCommunicator> _socket;
  char *_data;
  int _length;
};

void BluetoothCommunicator::cleanup()
{
  auto now = uv_hrtime();

  _l2sockets_mutex.lock();
  for (auto it = this->_l2sockets_connecting.cbegin(); it != this->_l2sockets_connecting.cend() /* not hoisted */; /* no increment */)
  {
    if (now < it->second->expires())
    {
      log("cleanup %02x:%02x:%02x:%02x:%02x:%02x (handle %d) due to timeout connecting\n", ADDRESS_LOG(it->second->address), it->second->handle);
      it->second->reason = "connection timeout";
      this->_l2sockets_connecting.erase(it++); // or "it = m.erase(it)" since C++11
    }
    else
    {
      ++it;
    }
  }
  _l2sockets_mutex.unlock();
}

NAN_METHOD(BluetoothHciSocket::Cleanup)
{
  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  Local<Function> callback = info[0].As<Function>();
  Nan::Callback *nanCallback = new Nan::Callback(callback);

  BluetoothCleanupWorker *worker = new BluetoothCleanupWorker(nanCallback, p->_communicator);
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(BluetoothHciSocket::New)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = new BluetoothHciSocket();
  p->Wrap(info.This());
  p->This.Reset(info.This());
  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(BluetoothHciSocket::Start)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  p->start();

  info.GetReturnValue().SetUndefined();
}

NAN_METHOD(BluetoothHciSocket::BindRaw)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  int devId = 0;
  int *pDevId = nullptr;

  if (info.Length() > 0)
  {
    Local<Value> arg0 = info[0];
    if (arg0->IsInt32() || arg0->IsUint32())
    {
      devId = Nan::To<int32_t>(arg0).FromJust();

      pDevId = &devId;
    }
  }

  devId = p->bindRaw(pDevId);

  info.GetReturnValue().Set(devId);
}

NAN_METHOD(BluetoothHciSocket::BindUser)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  int devId = 0;
  int *pDevId = nullptr;

  if (info.Length() > 0)
  {
    Local<Value> arg0 = info[0];
    if (arg0->IsInt32() || arg0->IsUint32())
    {
      devId = Nan::To<int32_t>(arg0).FromJust();

      pDevId = &devId;
    }
  }

  devId = p->bindUser(pDevId);

  info.GetReturnValue().Set(devId);
}

NAN_METHOD(BluetoothHciSocket::BindControl)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  p->bindControl();

  info.GetReturnValue().SetUndefined();
}

NAN_METHOD(BluetoothHciSocket::IsDevUp)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  bool isDevUp = p->isDevUp();

  info.GetReturnValue().Set(isDevUp);
}

NAN_METHOD(BluetoothHciSocket::GetDeviceList)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  struct hci_dev_list_req *dl;
  struct hci_dev_req *dr;

  dl = (hci_dev_list_req *)calloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl), 1);
  dr = dl->dev_req;

  dl->dev_num = HCI_MAX_DEV;

  Local<Array> deviceList = Nan::New<v8::Array>();

  if (ioctl(p->_communicator->_socket, HCIGETDEVLIST, dl) > -1)
  {
    int di = 0;
    for (int i = 0; i < dl->dev_num; i++, dr++)
    {
      uint16_t devId = dr->dev_id;
      bool devUp = dr->dev_opt & (1 << HCI_UP);
      // TODO: smells like there's a bug here (but dr isn't read so...)
      if (dr != nullptr)
      {
        v8::Local<v8::Object> obj = Nan::New<v8::Object>();
        Nan::Set(obj, Nan::New("devId").ToLocalChecked(), Nan::New<Number>(devId));
        Nan::Set(obj, Nan::New("devUp").ToLocalChecked(), Nan::New<Boolean>(devUp));
        Nan::Set(obj, Nan::New("idVendor").ToLocalChecked(), Nan::Null());
        Nan::Set(obj, Nan::New("idProduct").ToLocalChecked(), Nan::Null());
        Nan::Set(obj, Nan::New("busNumber").ToLocalChecked(), Nan::Null());
        Nan::Set(obj, Nan::New("deviceAddress").ToLocalChecked(), Nan::Null());
        Nan::Set(deviceList, di++, obj);
      }
    }
  }

  free(dl);

  info.GetReturnValue().Set(deviceList);
}

NAN_METHOD(BluetoothHciSocket::Info)
{
  char bdaddr[18];
  v8::Local<v8::Object> ret = Nan::New<v8::Object>();

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  p->_communicator->_l2sockets_mutex.lock();
  Local<Array> handles = Nan::New<v8::Array>();
  for (auto it = p->_communicator->_l2sockets_connected.begin(); it != p->_communicator->_l2sockets_connected.end(); ++it)
  {
    auto h = Nan::New<Number>(it->first);
    Nan::Set(handles, handles->Length(), h);
  }
  Nan::Set(ret, Nan::New("connectedHandles").ToLocalChecked(), handles);

  Local<Array> addresses = Nan::New<v8::Array>();
  for (auto it = p->_communicator->_l2sockets_connecting.begin(); it != p->_communicator->_l2sockets_connecting.end(); ++it)
  {
    snprintf(bdaddr, sizeof(bdaddr), "%02x:%02x:%02x:%02x:%02x:%02x", ADDRESS_LOG(it->first));
    auto h = Nan::New<String>(bdaddr).ToLocalChecked();
    Nan::Set(addresses, addresses->Length(), h);
  }
  Nan::Set(ret, Nan::New("connectingAddresses").ToLocalChecked(), addresses);
  p->_communicator->_l2sockets_mutex.unlock();

  info.GetReturnValue().Set(ret);
}

NAN_METHOD(BluetoothHciSocket::SetFilter)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  if (info.Length() > 0)
  {
    Local<Value> arg0 = info[0];
    if (arg0->IsObject())
    {
      p->setFilter(node::Buffer::Data(arg0), node::Buffer::Length(arg0));
    }
    else
    {
      Nan::ThrowTypeError("First argument must be a buffer");
      return;
    }
  }
  else
  {
    Nan::ThrowTypeError("Wrong number of arguments");
    return;
  }

  info.GetReturnValue().SetUndefined();
}

NAN_METHOD(BluetoothHciSocket::Stop)
{
  Nan::HandleScope scope;

  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  p->stop();

  info.GetReturnValue().SetUndefined();
}

NAN_METHOD(BluetoothHciSocket::Write)
{
  Nan::HandleScope scope;
  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  if (info.Length() >= 2)
  {
    Local<Value> arg0 = info[0];
    if (arg0->IsObject())
    {
      Local<Function> callback = info[1].As<Function>();
      Nan::Callback *nanCallback = new Nan::Callback(callback);

      auto data = node::Buffer::Data(arg0);
      auto length = node::Buffer::Length(arg0);

      if (p->_communicator->shouldWrite(data, length))
      {
        BluetoothWriteWorker *worker = new BluetoothWriteWorker(nanCallback, p->_communicator, data, length);
        worker->SaveToPersistent("data", arg0);
        Nan::AsyncQueueWorker(worker);
      }
      else
      {
        // printf("Skipping write of specific command\n");
        nanCallback->Call(0, nullptr);
      }
    }
    else
    {
      Nan::ThrowTypeError("First argument must be a buffer");
      return;
    }
  }
  else
  {
    Nan::ThrowTypeError("Wrong number of arguments");
    return;
  }

  info.GetReturnValue().SetUndefined();
}

NAN_METHOD(BluetoothHciSocket::KernelDisconnectWorkArounds)
{
  Nan::HandleScope scope;
  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  if (info.Length() >= 2)
  {
    Local<Value> arg0 = info[0];
    if (arg0->IsObject())
    {
      Local<Function> callback = info[1].As<Function>();
      int length = node::Buffer::Length(arg0);
      Nan::Callback *nanCallback = new Nan::Callback(callback);

      if (length == 22 || length == 7 || length == 34)
      {
        BluetoothDisconnectWorker *worker = new BluetoothDisconnectWorker(nanCallback, p->_communicator, node::Buffer::Data(arg0), length);
        worker->SaveToPersistent("data", arg0);
        Nan::AsyncQueueWorker(worker);
      }
      else
      {
        nanCallback->Call(0, nullptr);
        delete nanCallback;
      }
    }
    else
    {
      Nan::ThrowTypeError("Argument 0 must be a buffer");
      return;
    }
  }
  else
  {
    Nan::ThrowTypeError("Expected 2 arguments");
    return;
  }

  info.GetReturnValue().SetUndefined();
}

NAN_METHOD(BluetoothHciSocket::KernelConnectWorkArounds)
{
  Nan::HandleScope scope;
  BluetoothHciSocket *p = node::ObjectWrap::Unwrap<BluetoothHciSocket>(info.This());

  if (info.Length() >= 2)
  {
    Local<Value> arg0 = info[0];
    if (arg0->IsObject())
    {
      Local<Function> callback = info[1].As<Function>();
      int length = node::Buffer::Length(arg0);
      auto data = node::Buffer::Data(arg0);

      if (p->_communicator->shouldConnectWorkaround(data, length))
      {
        Nan::Callback *nanCallback = new Nan::Callback(callback);

        BluetoothConnectWorker *worker = new BluetoothConnectWorker(nanCallback, p->_communicator, data, length);
        worker->SaveToPersistent("data", arg0);
        Nan::AsyncQueueWorker(worker);
      }
    }
    else
    {
      Nan::ThrowTypeError("Argument 0 must be a buffer");
      return;
    }
  }
  else
  {
    Nan::ThrowTypeError("Expected 2 arguments");
    return;
  }

  info.GetReturnValue().SetUndefined();
}

void BluetoothHciSocket::PollCloseCallback(uv_poll_t *handle)
{
  BluetoothHciSocket *p = (BluetoothHciSocket *)handle->data;
  if (p->_communicator)
    close(p->_communicator->_socket);
  delete handle;
}

void BluetoothHciSocket::PollCallback(uv_poll_t *handle, int status, int events)
{
  BluetoothHciSocket *p = (BluetoothHciSocket *)handle->data;

  p->poll();
}

NODE_MODULE(binding, BluetoothHciSocket::Init);
