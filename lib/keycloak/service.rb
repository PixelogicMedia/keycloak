module Keycloak
  class Service

    def initialize(key_resolver)
      @key_resolver = key_resolver
      @logger = Keycloak.config.logger
      @token_expiration_tolerance_in_seconds = Keycloak.config.token_expiration_tolerance_in_seconds
    end

    def decode(token)
      unless token.nil? || token.empty?
        public_key = @key_resolver.find_public_keys
        JSON::JWT.decode(token, public_key)
      else
        raise TokenError.no_token(token)
      end
    end

    def decode_and_verify(token)
      decoded_token = decode(token)
      unless expired?(decoded_token)
        public_key = @key_resolver.find_public_keys
        decoded_token.verify!(public_key)
        decoded_token
      else
        raise TokenError.expired(token)
      end
    rescue JSON::JWT::VerificationFailed => e
      raise TokenError.verification_failed(token, e)
    rescue JSON::JWK::Set::KidNotFound => e
      raise TokenError.verification_failed(token, e)
    rescue JSON::JWT::InvalidFormat
      raise TokenError.invalid_format(token, e)
    end

    private

    def expired?(token)
      token_expiration = Time.at(token["exp"]).to_datetime
      token_expiration < Time.now + @token_expiration_tolerance_in_seconds.seconds
    end
  end
end
