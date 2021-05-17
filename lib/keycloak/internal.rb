module Keycloak
  module Internal
    include Keycloak::Admin

    class << self
    end

    def self.get_users(query_parameters = nil)
      proc = lambda {|token|
        Keycloak::Admin.get_users(query_parameters, token["access_token"])
      }

      default_call(proc)
    end

    def self.change_password(user_id, redirect_uri = '')
      proc = lambda {|token|
        Keycloak.generic_request(token["access_token"],
                                 Keycloak::Admin.full_url("users/#{user_id}/execute-actions-email"),
                                 {:redirect_uri => redirect_uri, :client_id => Keycloak::Client.client_id},
                                 ['UPDATE_PASSWORD'],
                                 'PUT')
      }

      default_call(proc)
    end

    def self.forgot_password(user_login, redirect_uri = '')
      user = get_user_info(user_login, true)
      change_password(user['id'], redirect_uri)
    end

    def self.get_logged_user_info
      proc = lambda {|token|
        userinfo = JSON Keycloak::Client.get_userinfo
        Keycloak.generic_request(token["access_token"],
                                 Keycloak::Admin.full_url("users/#{userinfo['sub']}"),
                                 nil, nil, 'GET')
      }

      default_call(proc)
    end

    def self.get_user_info(user_login, whole_word = false)
      proc = lambda { |token|
        if user_login.index('@').nil?
          search = {:username => user_login}
        else
          search = {:email => user_login}
        end
        users = JSON Keycloak.generic_request(token["access_token"],
                                              Keycloak::Admin.full_url("users/"),
                                              search, nil, 'GET')
        users[0]
        if users.count.zero?
          raise Keycloak::UserLoginNotFound
        else
          efective_index = -1
          users.each_with_index do |user, i|
            if whole_word
              efective_index = i if user_login == user['username'] || user_login == user['email']
            else
              efective_index = 0
            end
            break if efective_index >= 0
          end

          if efective_index >= 0
            if whole_word
              users[efective_index]
            else
              users
            end
          else
            raise Keycloak::UserLoginNotFound
          end
        end
      }

      default_call(proc)
    end

    def self.exists_name_or_email(value, user_id = '')
      begin
        usuario = Keycloak::Internal.get_user_info(value, true)
        if user_id.empty? || user_id != usuario['id']
          usuario.present?
        else
          false
        end
      rescue StandardError
        false
      end
    end

    def self.logged_federation_user?
      info = get_logged_user_info
      info['federationLink'] != nil
    end

    def self.create_simple_user(username, password, email, first_name, last_name, realm_roles_names, client_roles_names, email_verified = false,proc = nil)
      begin
        username.downcase!
        user = get_user_info(username, true)
        newUser = false
      rescue Keycloak::UserLoginNotFound
        newUser = true
      rescue => e
        e
        raise
      end

      proc_default = lambda { |token|
        user_representation = { username: username,
                                emailVerified: email_verified,
                                email: email,
                                firstName: first_name,
                                lastName: last_name,
                                enabled: true }

        if !newUser || Keycloak.generic_request(token["access_token"],
                                                Keycloak::Admin.full_url("users/"),
                                                nil, user_representation, 'POST')

          user = get_user_info(username, true) if newUser

          credential_representation = { type: "password",
                                        temporary: false,
                                        value: password }

          if user['federationLink'] != nil || Keycloak.generic_request(token["access_token"],
                                                                       Keycloak::Admin.full_url("users/#{user['id']}/reset-password"),
                                                                       nil, credential_representation, 'PUT')

            client = JSON Keycloak.generic_request(token["access_token"],
                                                   Keycloak::Admin.full_url("clients/"),
                                                   { clientId: Keycloak::Client.client_id }, nil, 'GET')

            if client_roles_names.count > 0
              roles = []
              client_roles_names.each do |r|
                if r.present?
                  role = JSON Keycloak.generic_request(token["access_token"],
                                                       Keycloak::Admin.full_url("clients/#{client[0]['id']}/roles/#{r}"),
                                                       nil, nil, 'GET')
                  roles.push(role)
                end
              end

              if roles.count > 0
                Keycloak.generic_request(token["access_token"],
                                         Keycloak::Admin.full_url("users/#{user['id']}/role-mappings/clients/#{client[0]['id']}"),
                                         nil, roles, 'POST')
              end
            end

            if realm_roles_names.count > 0
              roles = []
              realm_roles_names.each do |r|
                if r.present?
                  role = JSON Keycloak.generic_request(token["access_token"],
                                                       Keycloak::Admin.full_url("roles/#{r}"),
                                                       nil, nil, 'GET')
                  roles.push(role)
                end
              end

              if roles.count > 0
                Keycloak.generic_request(token["access_token"],
                                         Keycloak::Admin.full_url("users/#{user['id']}/role-mappings/realm"),
                                         nil, roles, 'POST')
              end
            else
              true
            end
          end
        end
      }

      if default_call(proc_default)
        proc.call user unless proc.nil?
      end
    end

    def self.create_starter_user(username, password, email, client_roles_names, proc = nil)
      Keycloak::Internal.create_simple_user(username, password, email, '', '', [], client_roles_names, proc)
    end

    def self.get_client_roles
      proc = lambda {|token|
        client = JSON Keycloak::Admin.get_clients({ clientId: Keycloak::Client.client_id }, token["access_token"])

        Keycloak.generic_request(token["access_token"],
                                 Keycloak::Admin.full_url("clients/#{client[0]['id']}/roles"),
                                 nil, nil, 'GET')
      }

      default_call(proc)
    end

    def self.get_client_user_roles(user_id)
      proc = lambda {|token|
        client = JSON Keycloak::Admin.get_clients({ clientId: Keycloak::Client.client_id }, token["access_token"])
        Keycloak::Admin.get_effective_client_level_role_composite_user(user_id, client[0]['id'], token["access_token"])
      }

      default_call(proc)
    end

    def self.has_role?(user_id, user_role)
      roles = JSON get_client_user_roles(user_id)
      if !roles.nil?
        roles.each do |role|
          return true if role['name'].to_s == user_role.to_s
        end
        false
      else
        false
      end
    end

    protected

    def self.default_call(proc)
      begin
        tk = nil
        resp = nil

        Keycloak::Client.get_installation

        payload = { 'client_id' => Keycloak::Client.client_id,
                    'client_secret' => Keycloak::Client.secret,
                    'grant_type' => 'client_credentials' }

        header = {'Content-Type' => 'application/x-www-form-urlencoded'}

        _request = -> do
          RestClient.post(Keycloak::Client.configuration['token_endpoint'], payload, header){|response, request, result|
            case response.code
            when 200..399
              tk = JSON response.body
              resp = proc.call(tk)
            else
              response.return!
            end
          }
        end

        Keycloak::Client.exec_request _request
      ensure
        if tk
          payload = { 'client_id' => Keycloak::Client.client_id,
                      'client_secret' => Keycloak::Client.secret,
                      'refresh_token' => tk["refresh_token"] }

          header = {'Content-Type' => 'application/x-www-form-urlencoded'}
          _request = -> do
            RestClient.post(Keycloak::Client.configuration['end_session_endpoint'], payload, header){|response, request, result|
              case response.code
              when 200..399
                resp if resp.nil?
              else
                response.return!
              end
            }
          end
          Keycloak::Client.exec_request _request
        end
      end
    end

  end

end