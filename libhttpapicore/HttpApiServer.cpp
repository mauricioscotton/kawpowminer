#include "HttpApiServer.h"

#include <kawpowminer/buildinfo.h>
#include <libethcore/Farm.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif


HttpApiServer::HttpApiServer(string address, int portnum, string password)
  : m_password(std::move(password)),
    m_address(address),
    m_acceptor(g_io_service),
    m_io_strand(g_io_service)
{
    if (portnum < 0)
    {
        m_portnumber = -portnum;
        m_readonly = true;
    }
    else
    {
        m_portnumber = portnum;
        m_readonly = false;
    }
}

void HttpApiServer::start()
{
    // cnote << "HttpApiServer::start";
    if (m_portnumber == 0)
        return;

    tcp::endpoint endpoint(boost::asio::ip::address::from_string(m_address), m_portnumber);

    // Try to bind to port number
    // if exception occurs it may be due to the fact that
    // requested port is already in use by another service
    try
    {
        m_acceptor.open(endpoint.protocol());
        m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        m_acceptor.bind(endpoint);
        m_acceptor.listen(64);
    }
    catch (const std::exception&)
    {
        cwarn << "Could not start HTTP API server on port: " +
                     to_string(m_acceptor.local_endpoint().port());
        cwarn << "Ensure port is not in use by another service";
        return;
    }

    cnote << "HTTP Api server listening on port " + to_string(m_acceptor.local_endpoint().port())
          << (m_password.empty() ? "." : ". Authentication needed.");
    m_workThread = std::thread{boost::bind(&HttpApiServer::begin_accept, this)};
    m_running.store(true, std::memory_order_relaxed);
}

void HttpApiServer::stop()
{
    // Exit if not started
    if (!m_running.load(std::memory_order_relaxed))
        return;

    m_acceptor.cancel();
    m_acceptor.close();
    m_workThread.join();
    m_running.store(false, std::memory_order_relaxed);

    // Dispose all sessions (if any)
    m_sessions.clear();
}

void HttpApiServer::begin_accept()
{
    if (!isRunning())
        return;

    auto session =
        std::make_shared<HttpApiConnection>(m_io_strand, ++lastSessionId, m_readonly, m_password);
    m_acceptor.async_accept(
        session->socket(), m_io_strand.wrap(boost::bind(&HttpApiServer::handle_accept, this,
                               session, boost::asio::placeholders::error)));
}

void HttpApiServer::handle_accept(
    std::shared_ptr<HttpApiConnection> session, boost::system::error_code ec)
{
    // Start new connection
    // cnote << "HttpApiServer::handle_accept";
    if (!ec)
    {
        session->onDisconnected([&](int id) {
            // Destroy pointer to session
            auto it = find_if(m_sessions.begin(), m_sessions.end(),
                [&id](const std::shared_ptr<HttpApiConnection> session) {
                    return session->getId() == id;
                });
            if (it != m_sessions.end())
            {
                auto index = std::distance(m_sessions.begin(), it);
                m_sessions.erase(m_sessions.begin() + index);
            }
        });
        m_sessions.push_back(session);
        cnote << "New API session from " << session->socket().remote_endpoint();
        session->start();
    }
    else
    {
        session.reset();
    }

    // Resubmit new accept
    begin_accept();
}

void HttpApiConnection::disconnect()
{
    // cnote << "HttpApiConnection::disconnect";

    // Cancel pending operations
    m_socket.cancel();

    if (m_socket.is_open())
    {
        boost::system::error_code ec;
        m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        m_socket.close(ec);
    }

    if (m_onDisconnected)
    {
        m_onDisconnected(this->getId());
    }
}

HttpApiConnection::HttpApiConnection(
    boost::asio::io_service::strand& _strand, int id, bool readonly, string password)
  : m_sessionId(id),
    m_socket(g_io_service),
    m_io_strand(_strand),
    m_readonly(readonly),
    m_password(std::move(password))
{
    m_jSwBuilder.settings_["indentation"] = "";
    if (!m_password.empty())
        m_is_authenticated = false;
}

void HttpApiConnection::start()
{
    // cnote << "HttpApiConnection::start";
    recvSocketData();
}

void HttpApiConnection::recvSocketData()
{
    boost::asio::async_read(m_socket, m_recvBuffer, boost::asio::transfer_at_least(1),
        m_io_strand.wrap(boost::bind(&HttpApiConnection::onRecvSocketDataCompleted, this,
            boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)));
}

std::string HttpApiConnection::buildHttpResponse(
    std::string body, std::string content_type, std::string http_code, std::string http_ver)
{
    std::stringstream ss;
    std::string s;
    ss << http_ver << " " << http_code
       << "Server: " << kawpowminer_get_buildinfo()->project_name_with_version << "\r\n"
       << "Content-Type: " << content_type << "\r\n"
       << "Content-Length: " << body.size() << "\r\n\r\n"
       << body << "\r\n";
    s = ss.str();
    ss.clear();
    return s;
}

Json::Value HttpApiConnection::jsonObjectResult(Json::Value val, std::string const prop = "result")
{
    Json::Value response;
    response[prop] = val;
    return response;
}


Json::Value HttpApiConnection::jsonObjectError(Json::Value val)
{
    return jsonObjectResult(val, "error");
}


Json::Value HttpApiConnection::parseJson(std::string& jsonBody)
{
    Json::Value result;
    Json::Reader read;
    if (read.parse(jsonBody, result))
        return result;
    else 
        return Json::Value::null;
}

void HttpApiConnection::onRecvSocketDataCompleted(
    const boost::system::error_code& ec, std::size_t bytes_transferred)
{
    /*
    Standard http request detection pattern
    1st group : any UPPERCASE word
    2nd group : the path
    3rd group : HTTP version
    */
    static std::regex http_pattern("^([A-Z]{1,6}) (\\/[\\S]*) (HTTP\\/1\\.[0-9]{1})");
    static std::regex http_post_body_pattern("^(?:\\n|\\r\\n)(?:.|\\r|\\n)+");
    static std::regex http_auth_pattern("^Authorization: Bearer (.+)");

    std::smatch http_matches;

    if (!ec && bytes_transferred > 0)
    {
        // Extract received message and free the buffer
        std::string rx_message(
            boost::asio::buffer_cast<const char*>(m_recvBuffer.data()), bytes_transferred);
        m_recvBuffer.consume(bytes_transferred);
        m_message.append(rx_message);

        // std::string line;
        // std::string linedelimiter;
        // std::size_t linedelimiteroffset;

        if (m_message.size() < 4)
            return;  // Wait for other data to come in

        std::regex_search(
            m_message, http_matches, http_pattern, std::regex_constants::match_default);

        std::string http_method = http_matches[1].str();
        std::string http_path = http_matches[2].str();
        std::string http_ver = http_matches[3].str();

        std::smatch post_body_match;
        Json::Value post_body;

        bool authenticated = false;
        bool requires_auth = !m_password.empty();

        // Do we support method ?
        if (http_method != "GET" && http_method != "POST")
        {
            std::string what = "Method " + http_method + " not allowed";
            NotAllowed405(what);
        }

        //Parse posted json body
        if (http_method == "POST")
        {
            std::regex_search(m_message, post_body_match, http_post_body_pattern,
                std::regex_constants::match_default);

            post_body = parseJson(post_body_match[0].str());
        }

        // Do we require authentication? If so, then is user authenticated?
        if (requires_auth)
        {
            std::smatch authTokenMatches;
            std::regex_search(m_message, authTokenMatches, http_auth_pattern,
                std::regex_constants::match_default);
            if (authTokenMatches[1].str() == m_password)
            {
                authenticated = true;
            }
            else
            {
                Unauthorized401();
                m_message.clear();
                return;
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////////
        //  API ENDPOINTS:
        ///////////////////////////////////////////////////////////////////////////////////////


        /**
            Gets miner simple details
        */
        if (http_method == "GET" && http_path == "/getstat1")
        {
            Json::Value stats = getMinerStat1();
            OK200(stats);
        }

        /**
            Gets miner full details
        */
        else if (http_method == "GET" && http_path == "/getstatdetail")
        {
            Json::Value stats = getMinerStatDetail();
            OK200(stats);
        }

        /**
            Ping
        */
        else if (http_method == "GET" && http_path == "/ping")
        {
            OK200(toString("pong"));
        }

        /**
            Gets connection list
        */
        else if (http_method == "GET" && http_path == "/getconnections")
        {
            Json::Value stats = PoolManager::p().getConnectionsJson();
            OK200(stats);
        }

        /**
            Gets scrambler info
        */
        else if (http_method == "GET" && http_path == "/getscramblerinfo" && requires_auth)
        {
            Json::Value stats = Farm::f().get_nonce_scrambler_json();
            OK200(stats);
        }

        /**
            Shuffles?
        */
        else if (http_method == "POST" && http_path == "/shuffle" && requires_auth && authenticated)
        {
            try
            {
                Farm::f().shuffle();
                OK200(jsonObjectResult("true"));
            }
            catch (...)
            {
                OK200(jsonObjectResult("false"));
            }
        }

        /**
            Restarts miner
        */
        else if (http_method == "POST" && http_path == "/restart" && requires_auth && authenticated)
        {
            try
            {
                Farm::f().restart_async();
                OK200(jsonObjectResult("true"));
            }
            catch (...)
            {
                OK200(jsonObjectResult("false"));
            }
        }

        /**
            Reboots miner?
        */
        else if (http_method == "POST" && http_path == "/reboot" && requires_auth && authenticated)
        {
            std::string rebooted = Farm::f().reboot({{"api_miner_reboot"}}) ? "true" : "false";
            OK200(jsonObjectResult(rebooted));
        }

        /**
            Adds connection
        */
        else if (http_method == "POST" && http_path == "/addconnection" && requires_auth &&
                 authenticated)
        {
            if (post_body != Json::Value::null && post_body.isMember("uri"))
            {
                PoolManager::p().addConnection(post_body["uri"].asString());
                OK200(jsonObjectResult("true"));
            } 
            else
            {
                OK200(jsonObjectResult("false"));
            }
        }

        /**
            Sets active connection
        */
        else if (http_method == "POST" && http_path == "/setactiveconnection" && requires_auth &&
                 authenticated)
        {
            if (post_body != Json::Value::null &&
                (post_body.isMember("uri") || post_body.isMember("index")))
            {
                try
                {
                    if (post_body.isMember("uri"))
                        PoolManager::p().setActiveConnection(post_body["uri"].asString());
                    else
                        PoolManager::p().setActiveConnection(post_body["index"].asUInt());
                    OK200(jsonObjectResult("true"));                 
                }
                catch (const std::exception& _ex)
                {
                    clog << _ex.what();
                    OK200(jsonObjectError(_ex.what()));
                }                
            }
            else
            {
                OK200(jsonObjectResult("false"));
            }
        }

        /**
            Removes connection
        */
        else if (http_method == "POST" && http_path == "/removeconnection" && requires_auth &&
                 authenticated)
        {
            if (post_body != Json::Value::null && post_body.isMember("index"))
            {
                try
                {
                    PoolManager::p().setActiveConnection(post_body["index"].asUInt());
                    OK200(jsonObjectResult("true"));                 
                }
                catch (const std::exception& _ex)
                {
                    clog << _ex.what();
                    OK200(jsonObjectError(_ex.what()));
                }                
            }
            else
            {
                OK200(jsonObjectResult("false"));
            }

        }

        /**
            Sets scrambler nonce
        */
        else if (http_method == "POST" && http_path == "/setscramblerinfo" && requires_auth &&
                 authenticated)
        {
            OK200(toString("METHOD NOT IMPLEMENTED YET"));

            /*
            
                    Json::Value jRequestParams;
                if (!getRequestValue("params", jRequestParams, jRequest, false, jResponse))
                    return;

                bool any_value_provided = false;
                uint64_t nonce = Farm::f().get_nonce_scrambler();
                unsigned exp = Farm::f().get_segment_width();

                if (jRequestParams.isMember("noncescrambler"))
                {
                    string nonceHex;

                    any_value_provided = true;

                    nonceHex = jRequestParams["noncescrambler"].asString();
                    if (nonceHex.substr(0, 2) == "0x")
                    {
                        try
                        {
                            nonce = std::stoul(nonceHex, nullptr, 16);
                        }
                        catch (const std::exception&)
                        {
                            jResponse["error"]["code"] = -422;
                            jResponse["error"]["message"] = "Invalid nonce";
                            return;
                        }
                    }
                    else
                    {
                        // as we already know there is a "noncescrambler" element we can use optional=false
                        if (!getRequestValue("noncescrambler", nonce, jRequestParams, false, jResponse))
                            return;
                    }
                }

                if (jRequestParams.isMember("segmentwidth"))
                {
                    any_value_provided = true;
                    if (!getRequestValue("segmentwidth", exp, jRequestParams, false, jResponse))
                        return;
                }

                if (!any_value_provided)
                {
                    jResponse["error"]["code"] = -32602;
                    jResponse["error"]["message"] = "Missing parameters";
                    return;
                }

                if (exp < 10)
                    exp = 10;  // Not below
                if (exp > 50)
                    exp = 40;  // Not above
                Farm::f().set_nonce_scrambler(nonce);
                Farm::f().set_nonce_segment_width(exp);
                jResponse["result"] = true;
            
            */


        }

        /**
            Pauses miner by index
        */
        else if (http_method == "POST" && http_path == "/pause" && requires_auth &&
                 authenticated)
        {
            if (post_body != Json::Value::null && post_body.isMember("index"))
            {
                auto const& miner = Farm::f().getMiner(post_body["index"].asUInt());
                if (miner)
                {
                    miner->pause(MinerPauseEnum::PauseDueToAPIRequest);
                    OK200(jsonObjectResult("true"));
                }
                else
                {
                    OK200(jsonObjectError("Index out of bounds"));
                }
            }
            else
            {
                OK200(jsonObjectResult("false"));
            }
        }

        /**
            Resumes miner by index
        */
        else if (http_method == "POST" && http_path == "/resume" && requires_auth &&
                 authenticated)
        {
            if (post_body != Json::Value::null && post_body.isMember("index"))
            {
                auto const& miner = Farm::f().getMiner(post_body["index"].asUInt());
                if (miner)
                {
                    miner->resume(MinerPauseEnum::PauseDueToAPIRequest);
                    OK200(jsonObjectResult("true"));
                } 
                else 
                {
                    OK200(jsonObjectError("Index out of bounds"));                    
                }
            }
            else
            {
                OK200(jsonObjectResult("false"));
            }
        }

        /**
            Sets verbosity level
        */
        else if (http_method == "POST" && http_path == "/setverbosity" && requires_auth &&
                 authenticated)
        {
            if (post_body != Json::Value::null && post_body.isMember("verbosity"))
            {
                unsigned int verbosity = post_body["verbosity"].asUInt();
                cnote << "Setting verbosity level to " << verbosity;
                g_logOptions = verbosity;
                OK200(jsonObjectResult("true"));
            }
            else
            {
                OK200(jsonObjectResult("false"));
            }
        }


        else
        {
            NotFound404(toString(http_path + " not found."));
        }

        m_message.clear();
    }
    else
    {
        disconnect();
    }
}


void HttpApiConnection::OK200(std::string const& msg)
{
    sendSocketData(msg, "200 OK", "text/html; charset=utf-8");
}

void HttpApiConnection::OK200(Json::Value const& obj)
{
    sendSocketData(obj, "200 OK", "application/json");
}

void HttpApiConnection::Unauthorized401(std::string const& msg)
{
    sendSocketData(msg, "401 Unauthorized", "text/html; charset=utf-8");
}

void HttpApiConnection::NotFound404(std::string const& msg)
{
    sendSocketData(msg, "404 Not Found", "text/html; charset=utf-8");
}

void HttpApiConnection::NotFound404(Json::Value const& obj)
{
    sendSocketData(obj, "404 Not Found", "application/json");
}

void HttpApiConnection::NotAllowed405(std::string const& msg)
{
    sendSocketData(msg, "405 Method not allowed", "text/html; charset=utf-8");
}

void HttpApiConnection::NotAllowed405(Json::Value const& obj)
{
    sendSocketData(obj, "405 Method not allowed", "application/json");
}


void HttpApiConnection::sendSocketData(Json::Value const& jReq, std::string const& http_code,
    std::string const& content_type, bool _disconnect)
{
    if (!m_socket.is_open())
        return;
    std::stringstream line;
    line << Json::writeString(m_jSwBuilder, jReq) << std::endl;
    sendSocketData(line.str(), http_code, content_type, true);
}

void HttpApiConnection::sendSocketData(std::string const& _s, std::string const& http_code,
    std::string const& content_type, bool _disconnect)
{
    if (!m_socket.is_open())
        return;
    std::ostream os(&m_sendBuffer);
    os << buildHttpResponse(_s, content_type, http_code);

    async_write(m_socket, m_sendBuffer,
        m_io_strand.wrap(boost::bind(&HttpApiConnection::onSendSocketDataCompleted, this,
            boost::asio::placeholders::error, _disconnect)));
}

void HttpApiConnection::onSendSocketDataCompleted(
    const boost::system::error_code& ec, bool _disconnect)
{
    if (ec || _disconnect)
        disconnect();
}

Json::Value HttpApiConnection::getMinerStat1()
{
    auto connection = PoolManager::p().getActiveConnection();
    TelemetryType t = Farm::f().Telemetry();
    auto runningTime =
        std::chrono::duration_cast<std::chrono::minutes>(steady_clock::now() - t.start);

    ostringstream poolAddresses;
    poolAddresses << connection->Host() << ':' << connection->Port();

    int gpuIndex;
    int numGpus = t.miners.size();

    Json::Value jRes;

    jRes["build"] = kawpowminer_get_buildinfo()->project_name_with_version;
    jRes["up_time"] = toString(runningTime.count());
    jRes["pool"] = poolAddresses.str();
    jRes["eth"]["hashrate"] = toString(t.farm.hashrate);
    jRes["eth"]["shares"]["accepted"] = toString(t.farm.solutions.accepted);
    jRes["eth"]["shares"]["rejected"] = toString(t.farm.solutions.rejected);
    jRes["eth"]["shares"]["invalid"] = toString(t.farm.solutions.failed);
    jRes["dcr"] = "Not supported";


    for (gpuIndex = 0; gpuIndex < numGpus; gpuIndex++)
    {
        TelemetryAccountType miner = t.miners.at(gpuIndex);
        jRes["threads"][gpuIndex]["hashrate"] = toString(miner.hashrate);
        jRes["threads"][gpuIndex]["paused"] = toString(miner.paused);
        jRes["threads"][gpuIndex]["prefix"] = toString(miner.prefix);

        jRes["threads"][gpuIndex]["sensors"]["temp"] = toString(miner.sensors.tempC);
        jRes["threads"][gpuIndex]["sensors"]["fan"] = toString(miner.sensors.fanP);
        jRes["threads"][gpuIndex]["sensors"]["power"] = toString(miner.sensors.powerW);

        jRes["threads"][gpuIndex]["shares"]["accepted"] = toString(miner.solutions.accepted);
        jRes["threads"][gpuIndex]["shares"]["rejected"] = toString(miner.solutions.rejected);
        jRes["threads"][gpuIndex]["shares"]["failed"] = toString(miner.solutions.failed);
        // jRes["threads"][gpuIndex]["shares"]["tstamp"] = toString(miner.solutions.tstamp);
        jRes["threads"][gpuIndex]["shares"]["wasted"] = toString(miner.solutions.wasted);
    }
    return jRes;
}

Json::Value HttpApiConnection::getMinerStatDetailPerMiner(
    const TelemetryType& _t, std::shared_ptr<Miner> _miner)
{
    unsigned _index = _miner->Index();
    std::chrono::steady_clock::time_point _now = std::chrono::steady_clock::now();

    Json::Value jRes;
    DeviceDescriptor minerDescriptor = _miner->getDescriptor();

    jRes["_index"] = _index;
    jRes["_mode"] =
        (minerDescriptor.subscriptionType == DeviceSubscriptionTypeEnum::Cuda ? "CUDA" : "OpenCL");

    /* Hardware Info */
    Json::Value hwinfo;
    hwinfo["bus_id"] = minerDescriptor.uniqueId;
    hwinfo["type"] =
        (minerDescriptor.type == DeviceTypeEnum::Gpu ?
                "GPU" :
                (minerDescriptor.type == DeviceTypeEnum::Accelerator ? "ACCELERATOR" : "CPU"));
    ostringstream ss;
    ss << (minerDescriptor.clDetected ? minerDescriptor.clName : minerDescriptor.cuName) << " "
       << dev::getFormattedMemory((double)minerDescriptor.totalMemory);
    hwinfo["name"] = ss.str();

    /* Hardware Sensors*/
    Json::Value sensors = Json::Value();

    sensors["temp"] = _t.miners.at(_index).sensors.tempC;
    sensors["fan"] = _t.miners.at(_index).sensors.fanP;
    sensors["power"] = _t.miners.at(_index).sensors.powerW;

    hwinfo["sensors"] = sensors;

    /* Mining Info */
    Json::Value mininginfo;


    Json::Value jshares = Json::Value();
    jshares["accepted"] = _t.miners.at(_index).solutions.accepted;
    jshares["rejected"] = _t.miners.at(_index).solutions.rejected;
    jshares["failed"] = _t.miners.at(_index).solutions.failed;
    auto solution_lastupdated = std::chrono::duration_cast<std::chrono::seconds>(
        _now - _t.miners.at(_index).solutions.tstamp);
    // interval in seconds from last found share
    jshares["lastupdated"] = uint64_t(solution_lastupdated.count());

    mininginfo["shares"] = jshares;
    mininginfo["paused"] = _miner->paused();
    mininginfo["pause_reason"] = _miner->paused() ? _miner->pausedString() : Json::Value::null;

    /* Nonce infos */
    Json::Value jsegment = Json::Value(Json::arrayValue);
    auto segment_width = Farm::f().get_segment_width();
    uint64_t gpustartnonce = Farm::f().get_nonce_scrambler() + ((uint64_t)_index << segment_width);
    jsegment.append(toHex(uint64_t(gpustartnonce), HexPrefix::Add));
    jsegment.append(toHex(uint64_t(gpustartnonce + (1LL << segment_width)), HexPrefix::Add));
    mininginfo["segment"] = jsegment;

    /* Hash & Share infos */
    mininginfo["hashrate"] = toString((uint32_t)_t.miners.at(_index).hashrate);

    jRes["hardware"] = hwinfo;
    jRes["mining"] = mininginfo;

    return jRes;
}

/**
 * @brief Return a total and per GPU detailed list of current status
 * As we return here difficulty and share counts (which are not getting resetted if we
 * switch pool) the results may "lie".
 * Eg: Calculating runtime, (current) difficulty and submitted shares must not match the hashrate.
 * Inspired by Andrea Lanfranchi comment on issue 1232:
 *    https://github.com/gangnamtestnet/kawpowminer/pull/1232#discussion_r193995891
 * @return The json result
 */
Json::Value HttpApiConnection::getMinerStatDetail()
{
    const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
    TelemetryType t = Farm::f().Telemetry();

    auto runningTime = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - t.start);

    // ostringstream version;
    Json::Value devices = Json::Value(Json::arrayValue);
    Json::Value jRes;

    /* Host Info */
    Json::Value hostinfo;
    hostinfo["version"] = kawpowminer_get_buildinfo()->project_name_with_version;  // miner version.
    hostinfo["runtime"] = uint64_t(runningTime.count());  // running time, in seconds.

    {
        // Even the client should know which host was queried
        char hostName[HOST_NAME_MAX + 1];
        if (!gethostname(hostName, HOST_NAME_MAX + 1))
            hostinfo["name"] = hostName;
        else
            hostinfo["name"] = Json::Value::null;
    }


    /* Connection info */
    Json::Value connectioninfo;
    auto connection = PoolManager::p().getActiveConnection();
    connectioninfo["uri"] = connection->str();
    connectioninfo["connected"] = PoolManager::p().isConnected();
    connectioninfo["switches"] = PoolManager::p().getConnectionSwitches();

    /* Mining Info */
    Json::Value mininginfo;

    mininginfo["hashrate"] = toString(uint32_t(t.farm.hashrate));
    mininginfo["epoch"] = PoolManager::p().getCurrentEpoch();
    mininginfo["epoch_changes"] = PoolManager::p().getEpochChanges();
    mininginfo["difficulty"] = PoolManager::p().getCurrentDifficulty();

    Json::Value sharesinfo = Json::Value();
    sharesinfo["accepted"] = t.farm.solutions.accepted;
    sharesinfo["rejected"] = t.farm.solutions.rejected;
    sharesinfo["failed"] = t.farm.solutions.failed;

    auto solution_lastupdated =
        std::chrono::duration_cast<std::chrono::seconds>(now - t.farm.solutions.tstamp);
    // interval in seconds from last found share
    sharesinfo["lastupdated"] = uint64_t(solution_lastupdated.count());

    mininginfo["shares"] = sharesinfo;

    /* Monitors Info */
    Json::Value monitorinfo;
    auto tstop = Farm::f().get_tstop();
    if (tstop)
    {
        Json::Value tempsinfo = Json::Value(Json::arrayValue);
        tempsinfo["start"] = Farm::f().get_tstart();
        tempsinfo["end"] = tstop;
        monitorinfo["temperatures"] = tempsinfo;
    }

    /* Devices related info */
    for (shared_ptr<Miner> miner : Farm::f().getMiners())
        devices.append(getMinerStatDetailPerMiner(t, miner));

    jRes["devices"] = devices;

    jRes["monitors"] = monitorinfo;
    jRes["connection"] = connectioninfo;
    jRes["host"] = hostinfo;
    jRes["mining"] = mininginfo;

    return jRes;
}
