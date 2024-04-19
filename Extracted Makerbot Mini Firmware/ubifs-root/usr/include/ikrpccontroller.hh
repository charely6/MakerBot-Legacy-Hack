#ifndef KRPCCONTROLLER_HH_
#define KRPCCONTROLLER_HH_

#include <memory>

namespace Json {
  class Value;
  class JsonRpcCallback;
}

// Clients using the code-generated kaitenstub.hh stub must pass in a ptr to
// obj that implements the below interface when constructing a KaitenStub.

namespace krpc {
class Controller {
 public:
  virtual void invoke(const char* method, const Json::Value& params,
                      const std::shared_ptr<JsonRpcCallback>& callback) = 0;
};

}  // namespace krpc

#endif  // KRPCCONTROLLER_HH_
