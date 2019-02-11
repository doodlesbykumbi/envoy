#include "extensions/filters/network/mysql_proxy/mysql_filter.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include "extensions/filters/network/mysql_proxy/mysql_go.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/assert.h"
#include "common/common/logger.h"

#include "extensions/filters/network/well_known_names.h"

#include "include/sqlparser/SQLParser.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

char* to_c_string(std::string str) {
  return &str[0u];;
}

MySQLFilterConfig::MySQLFilterConfig(const std::string& stat_prefix, Stats::Scope& scope)
    : scope_(scope), stat_prefix_(stat_prefix), stats_(generateStats(stat_prefix, scope)) {}

MySQLFilter::MySQLFilter(MySQLFilterConfigSharedPtr config) : config_(std::move(config)) {}

void MySQLFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
}

Network::FilterStatus MySQLFilter::onData(Buffer::Instance& data, bool) {
  auto requestingAuth = getSession().getState() == MySQLSession::State::MYSQL_CHALLENGE_REQ;
  doDecode(data);

  ENVOY_LOG(info, "onData");

  if (requestingAuth && !client_login_.isSSLRequest()) {
    if (client_login_.isSSLRequest()) {
      ENVOY_LOG(info, "this is an SSL request");
    }
    ENVOY_LOG(info, "requestingAuth");
    std::string user("kumbi");
    std::string password("password");
    std::string salt = server_greeting_.getSalt();

    client_login_.setUsername(user);

    std::string authResp = NativePassword(to_c_string(password), to_c_string(salt));
    client_login_.setAuthResp(authResp);

    std::string authPluginName("mysql_native_password");
    client_login_.setAuthPluginName(authPluginName);

    std::string client_login_data = client_login_.encode();
    std::string mysql_msg = MySQLProxy::BufferHelper::encodeHdr(client_login_data, 1);
    ENVOY_LOG(info, "AOK");
    data.drain(data.length());
    data.add(mysql_msg);
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus MySQLFilter::onWrite(Buffer::Instance& data, bool) {
  ENVOY_LOG(info, "onWrite");

  doDecode(data);

  auto initialising = getSession().getState() == MySQLSession::State::MYSQL_CHALLENGE_REQ;

  ENVOY_LOG(info, "onData");
  if (initialising) {
    ENVOY_LOG(info, "I guess we are initialising");
    std::string server_greeting_data = server_greeting_.encode();
    std::string server_greeting_msg = MySQLProxy::BufferHelper::encodeHdr(server_greeting_data, 0);

    data.drain(data.length());
    data.add(server_greeting_msg);
  }

  return Network::FilterStatus::Continue;
}

void MySQLFilter::doDecode(Buffer::Instance& buffer) {
  // Safety measure just to make sure that if we have a decoding error we keep going and lose stats.
  // This can be removed once we are more confident of this code.
  if (!sniffing_) {
//    buffer.drain(buffer.length());
    ENVOY_LOG(info, "not sniffing anymore");
    return;
  }

  // Clear dynamic metadata.
  envoy::api::v2::core::Metadata& dynamic_metadata =
      read_callbacks_->connection().streamInfo().dynamicMetadata();
  auto& metadata =
      (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy];
  metadata.mutable_fields()->clear();

  if (!decoder_) {
    decoder_ = createDecoder(*this);
  }

  try {
    decoder_->onData(buffer);
  } catch (EnvoyException& e) {
    ENVOY_LOG(info, "mysql_proxy: decoding error: {}", e.what());
    config_->stats_.decoder_errors_.inc();
    sniffing_ = false;
  }
}

DecoderPtr MySQLFilter::createDecoder(DecoderCallbacks& callbacks) {
  return std::make_unique<DecoderImpl>(callbacks);
}

void MySQLFilter::onProtocolError() { config_->stats_.protocol_errors_.inc(); }

void MySQLFilter::onNewMessage(MySQLSession::State state) {
  if (state == MySQLSession::State::MYSQL_CHALLENGE_REQ) {
    config_->stats_.login_attempts_.inc();
  }
}

void MySQLFilter::onServerGreeting(ServerGreeting& server_greeting) {
    server_greeting_ = server_greeting;
}

void MySQLFilter::onClientLogin(ClientLogin& client_login) {
  if (client_login.isSSLRequest()) {
    config_->stats_.upgraded_to_ssl_.inc();
  }

  client_login_ = client_login;
}

void MySQLFilter::onClientLoginResponse(ClientLoginResponse& client_login_resp) {
  if (client_login_resp.getRespCode() == MYSQL_RESP_AUTH_SWITCH) {
    config_->stats_.auth_switch_request_.inc();
  } else if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
  }
}

void MySQLFilter::onMoreClientLoginResponse(ClientLoginResponse& client_login_resp) {
  if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
  }
}

void MySQLFilter::onCommand(Command& command) {
  if (!command.isQuery()) {
    return;
  }

  // Parse a given query
  hsql::SQLParserResult result;
  hsql::SQLParser::parse(command.getData(), &result);

  ENVOY_CONN_LOG(trace, "mysql_proxy: query processed {}", read_callbacks_->connection(),
                 command.getData());

  if (!result.isValid()) {
    config_->stats_.queries_parse_error_.inc();
    return;
  }
  config_->stats_.queries_parsed_.inc();

  // Set dynamic metadata
  envoy::api::v2::core::Metadata& dynamic_metadata =
      read_callbacks_->connection().streamInfo().dynamicMetadata();
  ProtobufWkt::Struct metadata(
      (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy]);
  auto& fields = *metadata.mutable_fields();

  for (auto i = 0u; i < result.size(); ++i) {
    if (result.getStatement(i)->type() == hsql::StatementType::kStmtShow) {
      continue;
    }
    hsql::TableAccessMap table_access_map;
    result.getStatement(i)->tablesAccessed(table_access_map);
    for (auto it = table_access_map.begin(); it != table_access_map.end(); ++it) {
      auto& operations = *fields[it->first].mutable_list_value();
      for (auto ot = it->second.begin(); ot != it->second.end(); ++ot) {
        operations.add_values()->set_string_value(*ot);
      }
    }
  }

  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().MySQLProxy, metadata);
}

Network::FilterStatus MySQLFilter::onNewConnection() {
  config_->stats_.sessions_.inc();
  return Network::FilterStatus::Continue;
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
