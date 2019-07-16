module Keycloak
  module Client
    class << self
      attr_accessor :realm, :auth_server_url
      attr_reader :client_id, :secret, :configuration, :public_key
    end

    def self.get_token(user, password)
      setup_module

      payload = { 'client_id' => @client_id,
                  'client_secret' => @secret,
                  'username' => user,
                  'password' => password,
                  'grant_type' => 'password' }

      mount_request_token(payload)
    end

    def self.set_token(cookies, token)
      if token
        cookies[Keycloak.config.cookie_key] = {value: token, httponly: true, same_site: :strict}
        Keycloak.logger.debug("Set cookie")
      else
        Keycloak.logger.debug("Delete cookie")
        cookies.delete Keycloak.config.cookie_key
      end
    end

    def self.get_token_by_code(code, redirect_uri)
      verify_setup

      payload = { 'client_id' => @client_id,
                  'client_secret' => @secret,
                  'code' => code,
                  'grant_type' => 'authorization_code',
                  'redirect_uri' => redirect_uri }

      mount_request_token(payload)
    end

    def self.get_token_by_exchange(issuer, issuer_token)
      setup_module

      payload = { 'client_id' => @client_id, 'client_secret' => @secret, 'audience' => @client_id, 'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange', 'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token', 'subject_issuer' => issuer, 'subject_token' => issuer_token }
      header = {'Content-Type' => 'application/x-www-form-urlencoded'}
      _request = -> do
        RestClient.post(@configuration['token_endpoint'], payload, header){|response, request, result|
          # case response.code
          # when 200
          # response.body
          # else
          # response.return!
          # end
          response.body
        }
      end

      exec_request _request
    end

    def self.get_userinfo_issuer(access_token = '')
      verify_setup

      payload = { 'access_token' => access_token }
      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }
      _request = -> do
        RestClient.post(@configuration['userinfo_endpoint'], payload, header){ |response, request, result|
          response.body
        }
      end

      exec_request _request
    end

    def self.get_authorization_token(payload = {}, access_token = '')
      verify_setup

      payload = { 'grant_type' => 'urn:ietf:params:oauth:grant-type:uma-ticket' }.merge(payload)
      header = { 'Content-Type' => 'application/x-www-form-urlencoded', 'Authorization' => "Bearer #{access_token}" }
      _request = -> do
        RestClient.post(@configuration['token_endpoint'], payload, header){ |response, request, result|
          response.body
        }
      end

      exec_request _request
    end

    def self.get_token_by_refresh_token(refresh_token = '')
      verify_setup

      payload = { 'client_id' => @client_id,
                  'client_secret' => @secret,
                  'refresh_token' => refresh_token,
                  'grant_type' => 'refresh_token' }

      mount_request_token(payload)
    end

    def self.get_token_by_client_credentials(client_id = '', secret = '')
      setup_module

      client_id = @client_id if client_id.empty?
      secret = @secret if secret.empty?

      payload = { 'client_id' => client_id,
                  'client_secret' => secret,
                  'grant_type' => 'client_credentials' }

      mount_request_token(payload)
    end

    def self.get_token_introspection(token = '', client_id = '', secret = '')
      verify_setup

      payload = { 'token' => token }

      client_id = @client_id if client_id.empty?
      secret = @secret if secret.empty?

      authorization = Base64.strict_encode64("#{client_id}:#{secret}")
      authorization = "Basic #{authorization}"

      header = {'Content-Type' => 'application/x-www-form-urlencoded',
                'authorization' => authorization}

      _request = -> do
        RestClient.post(@configuration['token_introspection_endpoint'], payload, header){|response, request, result|
          case response.code
          when 200..399
            response.body
          else
            response.return!
          end
        }
      end

      exec_request _request
    end

    def self.url_login_redirect(redirect_uri, response_type = 'code')
      verify_setup

      p = URI.encode_www_form({ response_type: response_type, client_id: @client_id, redirect_uri: redirect_uri })
      "#{@configuration['authorization_endpoint']}?#{p}"
    end

    def self.logout(cookies, redirect_uri = '')
      verify_setup
      t = self.token(cookies)
      refresh_token = t.try(:[], 'refresh_token')
      if !refresh_token.blank?

        payload = { 'client_id' => @client_id,
                    'client_secret' => @secret,
                    'refresh_token' => refresh_token
        }

        header = {'Content-Type' => 'application/x-www-form-urlencoded'}

        if redirect_uri.empty?
          final_url = @configuration['end_session_endpoint']
        else
          final_url = "#{@configuration['end_session_endpoint']}?#{URI.encode_www_form({ redirect_uri: redirect_uri })}"
        end

        _request = -> do
          RestClient.post(final_url, payload, header){ |response, request, result|
            case response.code
            when 200..399
              set_token(cookies, nil)
              true
            else
              response.return!
            end
          }
        end

        exec_request _request
      else
        true
      end
    end

    def self.get_userinfo(access_token = '')
      verify_setup

      payload = { 'access_token' => access_token }

      header = { 'Content-Type' => 'application/x-www-form-urlencoded' }

      _request = -> do
        RestClient.post(@configuration['userinfo_endpoint'], payload, header){ |response, request, result|
          case response.code
          when 200
            response.body
          else
            response.return!
          end
        }
      end

      exec_request _request
    end

    def self.url_user_account
      verify_setup

      "#{@auth_server_url}/realms/#{@realm}/account"
    end

    def self.has_role?(user_role, access_token = '')
      verify_setup

      if user_signed_in?(access_token)
        dt = decoded_access_token(access_token)[0]
        dt = dt["resource_access"][@client_id]
        if dt != nil
          dt["roles"].each do |role|
            return true if role.to_s == user_role.to_s
          end
          false
        else
          false
        end
      else
        false
      end
    end

    def self.user_signed_in?(access_token = '')
      verify_setup

      begin
        JSON(get_token_introspection(access_token))['active'] === true
      rescue => e
        if e.class < Keycloak::KeycloakException
          raise
        else
          false
        end
      end
    end

    def self.get_attribute(attributeName, access_token = '')
      verify_setup

      attr = decoded_access_token(access_token)[0]
      attr[attributeName]
    end

    def self.token(cookies)
      cookie = cookies[Keycloak.config.cookie_key]
      cookie.present? ? JSON(cookie) : nil
    end

    def self.decoded_access_token(access_token = '')
      JWT.decode access_token, @public_key, false, { :algorithm => 'RS256' }
    end

    def self.decoded_refresh_token(refresh_token = '')
      JWT.decode refresh_token, @public_key, false, { :algorithm => 'RS256' }
    end

    private

    def self.get_installation
      if Keycloak.config.realm.blank? || Keycloak.config.auth_server_url.blank?
        raise "realm settings not found."
      else
        @realm = Keycloak.config.realm
        @auth_server_url = Keycloak.config.auth_server_url
        @client_id = Keycloak.config.client_id
        @secret = Keycloak.config.client_secret
        openid_configuration
      end
    end

    def self.verify_setup
      get_installation if @configuration.nil?
    end

    def self.setup_module
      get_installation
    end

    def self.exec_request(proc_request)
      if Keycloak.explode_exception
        proc_request.call
      else
        begin
          proc_request.call
        rescue RestClient::ExceptionWithResponse => err
          err.response
        end
      end
    end

    def self.openid_configuration
      RestClient.proxy = Keycloak.config.proxy unless Keycloak.config.proxy.empty?
      config_url = "#{@auth_server_url}/realms/#{@realm}/.well-known/openid-configuration"
      _request = -> do
        RestClient.get config_url
      end
      response = exec_request _request
      if response.code == 200
        @configuration = JSON response.body
      else
        response.return!
      end
    end

    def self.mount_request_token(payload)
      header = {'Content-Type' => 'application/x-www-form-urlencoded'}

      _request = -> do
        RestClient.post(@configuration['token_endpoint'], payload, header){|response, request, result|
          case response.code
          when 200
            response.body
          else
            response.return!
          end
        }
      end

      exec_request _request
    end

    def self.decoded_id_token(idToken = '')
      if idToken
        @decoded_id_token = JWT.decode idToken, @public_key, false, { :algorithm => 'RS256' }
      end
    end

  end

end