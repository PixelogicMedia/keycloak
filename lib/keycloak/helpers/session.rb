module Keycloak
  module Helpers
    module Session

      extend ActiveSupport::Concern

      included do
        if respond_to?(:helper_method)
          helper_method :current_user, :user_signed_in?, :sign_out!, :user_access_token
        end
        # prepend_before_action Proc.new {Keycloak.cookies = cookies}
      end

      def current_user
        return @current_user if @current_user.present?
        token = Keycloak::Client.token(cookies)
        return nil unless token
        begin
          decoded_token = Keycloak.service.decode_and_verify(token['access_token'])
          @current_user = ::User.find_by_email(decoded_token['email'])
          @current_user.keycloak_id = decoded_token['sub'] if @current_user.respond_to?(:keycloak_id=)
          return @current_user
        rescue TokenError => e
          if e.reason == :expired
            begin
              refresh_token(token)
              token = Keycloak::Client.token(cookies)
              decoded_token = Keycloak.service.decode_and_verify(token['access_token'])
              @current_user = ::User.find_by_email(decoded_token['email'])
              @current_user.keycloak_id = decoded_token['sub'] if @current_user.respond_to?(:keycloak_id=)
              return @current_user
            rescue
              nil
            end
          end
        rescue
          nil
        end
        Keycloak::Client.set_token(cookies, nil)
        nil
      end

      def user_signed_in?
        current_user.present?
      end

      def sign_out!
        Keycloak::Client.logout(cookies, '')
      end

      def user_access_token
        Keycloak::Client.token(cookies)['access_token']
      end

      def authenticate_user!
        token = Keycloak::Client.token(cookies)
        if token
          begin
            Keycloak.service.decode_and_verify(token['access_token'])
          rescue TokenError
            second_authentication_try(token)
          end
        else
          unauthenticated_redirect
        end
      end

      protected

      def redirect_to_session_history
        if session[Keycloak.session_history].present?
          url = session[Keycloak.session_history]
          session[Keycloak.session_history] = nil
          redirect_to url
        else
          redirect_to root_path
        end
      end

      def store_session_history
        if request.get? and request.url.size < 256
          Keycloak.logger.debug("Set history #{request.url}")
          session[Keycloak.session_history] = request.url
        end
      end

      def unauthenticated_redirect
        Keycloak.logger.debug("Unauthenticated redirect")
        store_session_history
        url = Rails.application.routes.url_helpers.url_for controller: "/#{Keycloak.config.keycloak_controller}", action: Keycloak.config.auth_callback_action
        redirect_to Keycloak::Client.url_login_redirect(url, response_type = 'code')
      end

      private

      def refresh_token(token)
        begin

          Keycloak.logger.debug("Refreshing token")
          # t = Keycloak.service.decode_and_verify(token['refresh_token'])
          Keycloak.logger.debug(token['refresh_token'])
          new_token = Keycloak::Client.get_token_by_refresh_token(token['refresh_token'])

          Keycloak::Client.set_token(cookies, new_token)
          new_token
        rescue
          nil
        end

      end

      def second_authentication_try(token)
        begin
          refresh_token(token)
        rescue
          Keycloak.logger.debug("Refresh token failed, redirecting to SSO")
          unauthenticated_redirect
        end
      end


    end

  end
end