#include<iostream>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"

const char *request = "" \
    "GET /index.html?param1=value1&param2=value1&param3=value1 HTTP/\n" \
    "AuThOrIzAtIoN: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\n" \
    "Host: localhost\n" \
    "Content-Length: 27\n" \
    "Content-Type: application/x-www-form-urlencoded\n";

int main() {
  std::cout<<"Hello world!\n";
  modsecurity::actions::disruptive::AllowType TYPE;
  modsecurity::ModSecurity* modsec = new modsecurity::ModSecurity();
  modsecurity::RulesSet* rules = new modsecurity::RulesSet();
  // modsecurity::Rules* rules = new modsecurity::Rules();
  modsec->setConnectorInformation("ModSecurity-test v0.0.1-alpha (ModSecurity test)");


    std::string json("");
    const char *err = NULL;
    int ret = 0;

    ret = modsec->processContentOffset(request, strlen(request),
        "o0,4v64,13v114,4v130,14v149,12t:lowercase", &json, &err);

    if (ret >= 0) {
        std::cout << json << std::endl;
    } else {
        std::cout << err << std::endl;
    }

  std::cout<<"Hello world!\n";
}