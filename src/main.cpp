#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http.h>
#include <pistache/net.h>
#include "pqc_service.h"
#include <nlohmann/json.hpp>

using namespace Pistache;
using json = nlohmann::json;

void setupRoutes(Rest::Router& router, PQCService& pqcService) {
    
    Rest::Routes::Get(router, "/generate_keys", [&](const Rest::Request&, Http::ResponseWriter response) -> Rest::Route::Result {
        try {
            auto [pub, priv] = pqcService.generate_keypair();
            json j;
            j["public_key"] = pub;
            j["private_key"] = priv;
            j["note"] = "Keep your private key safe. The public key can be shared.";
            response.send(Http::Code::Ok, j.dump(), MIME(Application, Json));
        } catch (const std::exception& e) {
            response.send(Http::Code::Internal_Server_Error, std::string("Key generation error: ") + e.what());
        }
    });

    Rest::Routes::Post(router, "/encrypt_data", [&](const Rest::Request& request, Http::ResponseWriter response) -> Rest::Route::Result {
        try {
            const auto& body = request.body();
            std::string result = pqcService.encrypt_data(body);
            
            if (result.rfind("Encryption failed:", 0) == 0) {
                response.send(Http::Code::Internal_Server_Error, result);
            } else {
                response.send(Http::Code::Ok, result, MIME(Application, Json));
            }

        } catch (const std::exception& e) {
            response.send(Http::Code::Internal_Server_Error, std::string("Exception: ") + e.what());
        }

        return Rest::Route::Result::Ok;
    });

    Rest::Routes::Post(router, "/decrypt_data", [&](const Rest::Request& request, Http::ResponseWriter response) -> Rest::Route::Result {
        try {
            auto body = request.body();
            nlohmann::json result = pqcService.decrypt_data(body);

            response.send(Http::Code::Ok, result.dump(4), MIME(Application, Json));
        } catch (const std::exception& e) {
            response.send(Http::Code::Internal_Server_Error, std::string("Decryption error: ") + e.what());
        }

        return Rest::Route::Result::Ok;
    });

    Rest::Routes::Post(router, "/encrypt", [&](const Rest::Request& request, Http::ResponseWriter response) -> Rest::Route::Result {
    auto body = request.body();
    auto ciphertext = pqcService.encrypt(body);
    response.send(Http::Code::Ok, "{\"ciphertext\":\"" + ciphertext + "\"}", MIME(Application, Json));
    return Rest::Route::Result::Ok;
    });

    /*Rest::Routes::Post(router, "/decrypt", [&](const Rest::Request& request, Http::ResponseWriter response) -> Rest::Route::Result {
    auto body = request.body();
    auto plaintext = pqcService.decrypt(body);
    response.send(Http::Code::Ok, "{\"plaintext\":\"" + plaintext + "\"}", MIME(Application, Json));
    return Rest::Route::Result::Ok;
    });*/

}

int main() {
    Http::Endpoint server(Address("*:9000"));
    auto opts = Http::Endpoint::options().threads(1).maxRequestSize(1024 * 1024 * 10);
    server.init(opts);

    PQCService pqcService;
    Rest::Router router;
    setupRoutes(router, pqcService);

    server.setHandler(router.handler());
    server.serve();
}
