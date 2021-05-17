require 'keycloak/version'
require 'keycloak/configuration'
require 'keycloak/helpers'
require 'keycloak/admin'
require 'keycloak/client'
require 'keycloak/internal'
require 'keycloak/service'
require 'keycloak/public_key_resolver'
require 'keycloak/public_key_cached_resolver'
require 'keycloak/token_error'
require 'rest-client'
require 'json'
require 'json/jwt'
require 'base64'
require 'uri'
require 'erb'
require 'logger'

module Keycloak

  class << self
    attr_accessor :cookies
  end

  def self.configure
    yield @configuration ||= Keycloak::Configuration.new
  end

  def self.public_key_resolver
    @public_key_resolver ||= Keycloak::PublicKeyCachedResolver.from_configuration(config)
  end

  def self.service
    @service ||= Keycloak::Service.new(public_key_resolver)
  end

  def self.config
    @configuration
  end

  def self.logger
    config.logger
  end

  def self.session_history
    "KEYCLOAK_SESSION_HISTORY"
  end

  def self.load_configuration
    logger = ::Logger.new(STDOUT)
    logger.level = ::Logger::DEBUG
    logger.progname = 'Keycloak'
    logger.formatter = proc do |severity, time, progname, msg|
      "[#{progname}][#{severity}] #{time}: \n\t#{msg} \n\n"
    end

    configure do |config|
      config.generate_request_exception = true
      config.keycloak_controller = 'session'
      config.auth_callback_action = 'signin'
      config.cookie_key = 'KEYCLOAK_TOKEN'
      config.realm = ''
      config.client_id = ''
      config.client_secret = ''
      config.auth_server_url = ''
      config.logger = logger
      config.token_expiration_tolerance_in_seconds = 10
      config.public_key_cache_ttl = 86400
      config.proxy = ''
    end
  end

  load_configuration


  def self.explode_exception
    Keycloak.config.generate_request_exception
  end

  private

  def self.generic_request(access_token, uri, query_parameters, body_parameter, method)
    Keycloak::Client.verify_setup
    final_url = uri

    header = {'Content-Type' => 'application/x-www-form-urlencoded',
              'Authorization' => "Bearer #{access_token}"}

    if query_parameters
      parameters = URI.encode_www_form(query_parameters)
      final_url = final_url << '?' << parameters
    end

    case method.upcase
    when 'GET'
      _request = -> do
        RestClient.get(final_url, header) {|response, request, result|
          rescue_response(response)
        }
      end
    when 'POST', 'PUT'
      header["Content-Type"] = 'application/json'
      parameters = JSON.generate body_parameter
      _request = -> do
        case method.upcase
        when 'POST'
          RestClient.post(final_url, parameters, header) {|response, request, result|
            rescue_response(response)
          }
        else
          RestClient.put(final_url, parameters, header) {|response, request, result|
            rescue_response(response)
          }
        end
      end
    when 'DELETE'
      _request = -> do
        if body_parameter
          header["Content-Type"] = 'application/json'
          parameters = JSON.generate body_parameter
          RestClient::Request.execute(method: :delete, url: final_url,
                                      payload: parameters, headers: header) {|response, request, result|
            rescue_response(response)
          }
        else
          RestClient.delete(final_url, header) {|response, request, result|
            rescue_response(response)
          }
        end
      end
    else
      raise
    end

    _request.call

  end

  def self.rescue_response(response)
    case response.code
    when 200..399
      if response.body.empty?
        true
      else
        response.body
      end
    when 400..499
      begin
        response.return!
      rescue RestClient::ExceptionWithResponse => err
        raise ActionController::RoutingError.new(err.message)
      end
    else
      if Keycloak.explode_exception
        response.return!
      else
        begin
          response.return!
        rescue RestClient::ExceptionWithResponse => err
          err.message
        rescue StandardError => e
          e.message
        end
      end
    end
  end
end

require 'keycloak/exceptions'