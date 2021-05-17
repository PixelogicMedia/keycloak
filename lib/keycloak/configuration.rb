require 'logger'
module Keycloak
  class Configuration
    include ActiveSupport::Configurable
    config_accessor :token_expiration_tolerance_in_seconds, :public_key_cache_ttl, :logger,
                    :proxy, :generate_request_exception, :keycloak_controller, :auth_callback_action,
                    :cookie_key, :realm, :auth_server_url, :client_id, :client_secret
  end
end
