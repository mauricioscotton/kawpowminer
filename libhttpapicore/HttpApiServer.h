#pragma once

#include <regex>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

#include <json/json.h>

#include <libethcore/Farm.h>
#include <libethcore/Miner.h>
#include <libpoolprotocols/PoolManager.h>

using namespace dev;
using namespace dev::eth;
using namespace std::chrono;

using boost::asio::ip::tcp;

class HttpApiConnection
{
public:

    HttpApiConnection(boost::asio::io_service::strand& _strand, int id, bool readonly, string password);

    ~HttpApiConnection() = default;

    void start();

    Json::Value getMinerStat1();

    using Disconnected = std::function<void(int const&)>;
    void onDisconnected(Disconnected const& _handler) { m_onDisconnected = _handler; }

    int getId() { return m_sessionId; }

    tcp::socket& socket() { return m_socket; }

private:
    void disconnect();
    void processRequest(Json::Value& jRequest, Json::Value& jResponse);
    void recvSocketData();
    void onRecvSocketDataCompleted(
        const boost::system::error_code& ec, std::size_t bytes_transferred);
    void sendSocketData(Json::Value const& jReq, std::string const& http_code,
        std::string const& content_type, bool _disconnect = false);
    void sendSocketData(std::string const& _s, std::string const& http_code,
        std::string const& content_type, bool _disconnect = true);
    void onSendSocketDataCompleted(const boost::system::error_code& ec, bool _disconnect = true);

    void OK200(std::string const& msg);
    void OK200(Json::Value const& obj);
    void Unauthorized401(std::string const& msg = "You are not authorized to perform this action");
    void NotFound404(std::string const& msg);
    void NotFound404(Json::Value const& obj);
    void NotAllowed405(std::string const& msg);
    void NotAllowed405(Json::Value const& obj);

    Json::Value getMinerStatDetail();
    Json::Value getMinerStatDetailPerMiner(const TelemetryType& _t, std::shared_ptr<Miner> _miner);

    Json::Value parseJson(std::string& jsonBody);
    Json::Value jsonObjectError(Json::Value val);
    Json::Value jsonObjectResult(Json::Value val, std::string const prop);
    std::string buildHttpResponse(std::string body, std::string content_type = "application/json",
        std::string http_code = "200 OK", std::string http_ver = "HTTP/1.1");

    Disconnected m_onDisconnected;

    int m_sessionId;

    tcp::socket m_socket;
    boost::asio::io_service::strand& m_io_strand;
    boost::asio::streambuf m_sendBuffer;
    boost::asio::streambuf m_recvBuffer;
    Json::StreamWriterBuilder m_jSwBuilder;

    std::string m_message;  // The internal message string buffer

    bool m_readonly = false;
    std::string m_password = "";

    bool m_is_authenticated = true;
};


class HttpApiServer
{
public:
    HttpApiServer(string address, int portnum, string password);
    bool isRunning() { return m_running.load(std::memory_order_relaxed); };
    void start();
    void stop();

private:
    void begin_accept();
    void handle_accept(std::shared_ptr<HttpApiConnection> session, boost::system::error_code ec);

    int lastSessionId = 0;

    std::thread m_workThread;
    std::atomic<bool> m_readonly = {false};
    std::string m_password = "";
    std::atomic<bool> m_running = {false};
    string m_address;
    uint16_t m_portnumber;
    tcp::acceptor m_acceptor;
    boost::asio::io_service::strand m_io_strand;
    std::vector<std::shared_ptr<HttpApiConnection>> m_sessions;
};
